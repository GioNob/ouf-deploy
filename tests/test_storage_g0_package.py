import json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from tools.storage_planning import g0_package as p,g0_host as h
from tools.storage_planning.inventory_manifest import canonical,sha
from test_storage_g0_database import fixture,raw_export

def put(path,value):path.write_bytes(value if type(value) is bytes else canonical(value));path.chmod(0o600);return str(path)
class PackageTest(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.bundle=self.root/'bundle';self.bundle.mkdir();self.inputs=self.root/'inputs';self.inputs.mkdir();self.history=self.root/'history';self.history.mkdir();self.output=self.root/'output';self.output.mkdir()
  put(self.bundle/'member',b'fixture');raw=canonical({'schema':'ouf.storage-g0-package.v1','runtimeAuthorityIssued':False,'files':{'member':sha(b'fixture')}});put(self.bundle/'package-manifest.json',raw);self.digest=sha(raw)
  secret=put(self.inputs/'secret',b'fixture');self.config={'schema':'ouf.storage-g0-package-input.v1','operationId':'fixture','installationRef':'fixture','outputParent':str(self.output),'roles':{role:{'containerId':format(i+1,'064x'),'nativeImage':'sha256:'+'a'*64} for i,role in enumerate(h.ROLES)},'capacityPaths':{k:str(self.root) for k in ('source','destination','backup')},'connectionFiles':{},'operatorEvidenceFiles':dict.fromkeys(p.OPERATOR),'priorReceiptFiles':[],'collectionDecisionRef':'fixture-reference-not-authentication'}
  for key in ['s3','onboarding','udp','ingestion']:
   c={'schema':'ouf.storage-g0-collection-input.v1' if key=='s3' else 'ouf.storage-g0-db-input.v1','operationId':'fixture-'+key,'installationRef':'fixture'}
   if key=='s3':c['connection']={'endpoint':'https://fixture.invalid','region':'us-east-1','accessKeyFile':secret,'secretKeyFile':secret}
   else:c.update(profile=key,host='127.0.0.1',hostaddr='127.0.0.1',port=5432,database='fixture',user='fixture',passwordFile=secret,sslmode='disable',rootCertificateFile='')
   self.config['connectionFiles'][key]=put(self.inputs/(key+'.json'),c)
  runtime={'schema':'ouf.storage-g0-operator-evidence.v1','installationRef':'fixture','section':'RUNTIME','provenance':'OPERATOR_DECLARATION','ownerRef':'fixture','capturedAt':'2026-11-05T00:00:00Z','evidenceRefs':['fixture-evidence'],'storageBuckets':{'onboarding':'ouf-managed-files','udp':'ouf-udp'}}
  self.config['operatorEvidenceFiles']['runtime']=put(self.inputs/'runtime.json',runtime)
  for i in range(1,18):
   b=canonical({'fixtureControl':i});path=put(self.history/str(i),b);self.config['priorReceiptFiles'].append({'control':i,'path':path,'sha256':sha(b)})
  self.path=self.inputs/'package.json';self.save()
 def save(self):put(self.path,self.config)
 def check(self):return p.preflight(self.path,self.bundle,self.digest)
 def test_preflight_zero_target_reads_and_no_authority(self):
  with patch.object(p,'Engine',side_effect=AssertionError('network')):r=self.check()[-1]
  self.assertEqual(r['targetReads'],0);self.assertFalse(r['targetCommandAuthorized']);self.assertEqual(len(r['operatorInputsMissing']),5);self.assertFalse((self.output/'fixture').exists())
 def test_missing_bucket_binding_denied_before_scope_or_network(self):
  self.config['operatorEvidenceFiles']['runtime']=None;self.save();self.assertRaises(ValueError,self.check);self.assertFalse((self.output/'fixture').exists())
 def test_changed_history_and_consumed_scope_denied(self):
  put(self.history/'17',b'changed');self.assertRaises(ValueError,self.check)
 def test_existing_scope_denies_reentry(self):
  (self.output/'fixture').mkdir();self.assertRaises(ValueError,self.check)
 def test_package_tamper_and_extra_member_denied(self):
  put(self.bundle/'unreviewed',b'new');self.assertRaises(ValueError,self.check)
 def test_cross_installation_and_profile_denied(self):
  path=Path(self.config['connectionFiles']['udp']);v=json.loads(path.read_text());v['installationRef']='another';put(path,v);self.assertRaises(ValueError,self.check)
 def test_missing_decision_never_creates_scope(self):
  self.config['collectionDecisionRef']=None;self.save();self.assertRaises(ValueError,p.collect,self.path,self.bundle,self.digest);self.assertFalse((self.output/'fixture').exists())
 def test_failure_consumes_single_parent_scope_and_preserves_history(self):
  with patch.object(p,'Engine',side_effect=ValueError('G0_FIXTURE_ENGINE_HELD')):r=p.collect(self.path,self.bundle,self.digest)
  self.assertFalse(r['technicalCaptureComplete']);self.assertTrue(r['scopeConsumed']);self.assertEqual(r['reason'],'G0_FIXTURE_ENGINE_HELD');self.assertTrue((self.output/'fixture/result.json').is_file());self.assertRaises(ValueError,self.check)
  self.assertTrue(all(sha(Path(x['path']).read_bytes())==x['sha256'] for x in self.config['priorReceiptFiles']))
 def test_host_redacts_secret_values_and_keeps_stopped_state(self):
  d={'Id':'a'*64,'Image':'sha256:'+'b'*64,'Name':'/fixture','State':{'Running':False,'Pid':0},'Config':{'Env':['PASSWORD=never-export-me','OUF_UDP_S3_BUCKET=fixture-bucket']}}
  r=h.selected(d);self.assertNotIn('never-export-me',canonical(r).decode());self.assertEqual(r['storageBindings']['OUF_UDP_S3_BUCKET'],'fixture-bucket');self.assertFalse(r['running'])
 def test_embedded_endpoint_secret_denied(self):
  d={'Id':'a'*64,'Image':'sha256:'+'b'*64,'Config':{'Env':['OUF_UDP_S3_ENDPOINT=https://user:password@host']}};self.assertRaises(ValueError,h.selected,d)
 def test_public_acl_and_unsupported_block_remain_review(self):
  inv={'bucketFeatures':[{'bucket':'fixture','acl':{'status':'PRESENT','value':{'Owner':{'ID':'owner'},'Grants':[{'Grantee':{'Type':'Group','URI':'http://acs.amazonaws.com/groups/global/AllUsers'},'Permission':'READ'}]}},'policy':{'status':'ABSENT'},'publicAccessBlock':{'status':'UNSUPPORTED'}}]};r=p.access_findings(inv);self.assertFalse(r['effectiveAuthorizationProven']);self.assertIn('ACL_BROAD_GROUP_REVIEW',[x['code'] for x in r['findings']]);self.assertIn('PUBLICACCESSBLOCK_UNSUPPORTED_REVIEW',[x['code'] for x in r['findings']])
 def test_cumulative_profile_has_no_retry_or_mutation_authority(self):
  self.assertEqual(p.LIMITS['priorControls'],17);self.assertEqual(p.LIMITS['priorEngineGets'],52);self.assertEqual(p.LIMITS['databaseExports'],3);self.assertEqual(p.LIMITS['engineGets'],130);self.assertFalse(p.LIMITS['automaticReplayAllowed'])
 def test_full_sequence_seals_eight_sections_without_acceptance(self):
  class FakeEngine:
   def __init__(self,scope):self.requests=0;self.bytes=0
  def host(engine,roles):engine.requests+=14;return {'findings':[],'roles':roles}
  rows={k:v['rows'] for e in fixture()[1].values() for k,v in e['sections'].items()}
  def sql_export(config,scope):
   v=json.loads(config.read_text());scope.mkdir();docs=[json.loads(x) for x in raw_export(v['profile'],rows).splitlines()];docs[0].update(database='fixture',role='fixture',serverAddress='127.0.0.1',serverPort=5432)
   put(scope/'export.private.jsonl',b'\n'.join(canonical(d) for d in docs)+b'\n');return {'complete':True}
  def body(args,**kwargs):
   from types import SimpleNamespace
   config=Path(args[2]);scope=Path(args[3]);scope.mkdir();inv={'bucketFeatures':[]};put(scope/'inventory-before.private.json',inv);c=fixture()[0];c.update(operationId='fixture-s3',installationRef='fixture',configSha256=sha(config.read_bytes()),inventoryBeforeSha256=sha(canonical(inv)));put(scope/'collection.private.json',c)
   return SimpleNamespace(returncode=0,stdout=canonical({'complete':True,'requestsReserved':72}),stderr=b'')
  with patch.object(p,'Engine',FakeEngine),patch.object(p,'snapshot',host),patch.object(p,'capacity',return_value={}),patch.object(p.subprocess,'run',body),patch.object(p.db,'export',sql_export):r=p.collect(self.path,self.bundle,self.digest)
  self.assertTrue(r['technicalCaptureComplete']);self.assertEqual(r['databaseExportsAttempted'],3);self.assertEqual(r['engineGets'],28);self.assertEqual(r['cumulativeEngineGets'],80);self.assertEqual(set(r['sections']),set(p.SECTIONS));self.assertEqual(r['sections']['OBJECTS']['verifiedBodies'],2);self.assertEqual(r['sections']['DB']['findings'],0);self.assertFalse(r['g0Complete']);self.assertFalse(r['operatorEvidenceAuthenticated']);self.assertEqual(r['sections']['WINDOW']['status'],'MISSING_OPERATOR_EVIDENCE')
if __name__=='__main__':unittest.main()
