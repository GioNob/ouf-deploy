import copy,hashlib,importlib,json,os,shutil,tempfile,unittest
from pathlib import Path
from tools.storage_planning import g0_input_draft as m
from tools.storage_migration.minio_input_observation import InputBinding

class InputDraftTests(unittest.TestCase):
 def setUp(self):
  self.oldmask=os.umask(0o077);self.root=Path(tempfile.mkdtemp(prefix='g0-input-test-',dir=Path('/var/lib') if os.environ.get('GITHUB_ACTIONS')=='true' else Path.cwd()));self.stage=self.root/'stage';self.stage.mkdir(mode=0o700)
  for n in ('inputs','package','evidence'):(self.stage/n).mkdir(mode=0o700)
  self.seed={'schema':'ouf.m2-discovery-current-private-bindings.v1','historicalAuthorityReused':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'bootId':'11111111-1111-1111-1111-111111111111','observations':{},'processPins':{}}
  self.roster={};self.env={};self.pin={};names=('apisix','caddy','gateway-owner','ingestion','ingestion-evidence-read','keycloak','mcp','minio','onboarding','postgres','semantic','udp','udp-evidence-read')
  for i,role in enumerate(names,2):
   cid=format(i,'064x');pin={'pid':100+i,'startTicks':1000+i,'namespaces':{'net':[4,2000+i],'mnt':[4,3000+i]}};doc={'Id':cid,'Image':'sha256:'+format(i+100,'064x'),'State':{'Pid':pin['pid']},'Name':'/'+role,'Config':{'Hostname':role},'NetworkSettings':{'Networks':{'n':{'Aliases':[role]}}},'Mounts':[{'Destination':'/data','Source':str(self.root/'source')}]};self.seed['observations'][role]=doc;self.seed['processPins'][role]=pin;self.roster[role]={'containerId':cid,'generation':pin};self.pin[pin['pid']]=pin
   self.env[pin['pid']]={}
  for role,prefix in m.DB_PREFIX.items():self.env[self.roster[role]['generation']['pid']]={prefix+'_DB_URL':'jdbc:postgresql://postgres:5432/ouf_'+role+'?currentSchema=ouf_'+role,prefix+'_DB_USER':'app_'+role,prefix+'_DB_PASSWORD':'fixture:secret\\value'}
  self.env[self.roster['onboarding']['generation']['pid']]['OUF_ONBOARDING_STAGING_BUCKET']='ouf-managed-files';self.env[self.roster['udp']['generation']['pid']]['OUF_UDP_S3_BUCKET']='ouf-udp'
  self.minioroot=self.root/'minio';(self.minioroot/'run/secrets').mkdir(mode=0o700,parents=True);(self.minioroot/'run/secrets/access').write_text('fixture-user');(self.minioroot/'run/secrets/secret').write_text('fixture-only-minio-password')
  self.env[self.roster['minio']['generation']['pid']]={'MINIO_ROOT_USER_FILE':'access','MINIO_ROOT_PASSWORD_FILE':'secret'}
  m.put(self.root/'seed.json',m.encoded(self.seed));manifest=m.encoded({'files':{}});(self.stage/'package/package-manifest.json').write_bytes(manifest)
  self.profile={'seedPath':str(self.root/'seed.json'),'seedCanonicalSha256':m.digest(self.seed),'roster':self.roster,'packageManifestSha256':m.sha(manifest),'operationId':'test-g0-once','installationRef':'test-installation','installationRefKind':'LOCAL_COLLECTION_CORRELATION_NOT_IAM_AUTHORITY','proposedPaths':{'destination':str(self.root/'future-data'),'backup':str(self.root/'future-staging')}}
  m.put(self.stage/'preparation.json',m.encoded({'manifestSha256':m.sha(manifest),'historyMatchesPreviousPreparation':True}));rows=[]
  for i in range(1,18):p=self.root/('receipt-'+str(i));m.put(p,m.encoded({'control':i}));rows.append({'control':i,'path':str(p),'sha256':m.sha(p.read_bytes())})
  self.original={'schema':'ouf.storage-g0-package-input.v2','operationId':None,'installationRef':None,'collectionDecisionRef':None,'roles':{r:{'containerId':None,'nativeImage':None} for r in names},'priorReceiptFiles':rows,'connectionFiles':{r:str(self.stage/'inputs'/(r+'.json')) for r in ('s3','onboarding','udp','ingestion')},'operatorEvidenceFiles':dict.fromkeys(('runtime','access','writers','capacity','custody','window')),'capacityPaths':dict.fromkeys(('source','destination','backup')),'networkBindingFile':str(self.stage/'inputs/network.json'),'outputParent':str(self.stage/'evidence')};m.put(self.stage/'inputs/package-input.json',m.encoded(self.original))
  self.reads=[]
 def tearDown(self):shutil.rmtree(self.root);os.umask(self.oldmask)
 def envread(self,pid):self.reads.append(pid);return self.env[pid]
 def factory(self,pid):
  fd=os.open(self.minioroot,os.O_RDONLY|os.O_DIRECTORY)
  try:return InputBinding(pid,root=fd,cwd=fd)
  finally:os.close(fd)
 def runprep(self,**kw):
  args={'env_reader':self.envread,'pin_reader':lambda pid:self.pin[pid],'boot_reader':lambda:self.seed['bootId'],'minio_factory':self.factory};args.update(kw);return m.prepare(self.stage,self.profile,**args)
 def draft(self):return self.stage/'inputs'/m.DRAFT
 def test_all_inputs_private_without_collection_or_secret_output(self):
  r=self.runprep();self.assertEqual(r['status'],'PRIVATE_INPUT_DRAFT_PREPARED_REVIEW_REQUIRED');self.assertEqual(sorted(r['connectionDraftsPrepared']),['ingestion','onboarding','s3','udp']);self.assertEqual(r['processEnvironmentsRead'],4);self.assertEqual(r['credentialFilesRead'],2);self.assertEqual(r['credentialFilesWritten'],5);self.assertTrue(r['credentialsMayBePresentInDraft']);self.assertFalse(list((self.stage/'evidence').iterdir()));self.assertNotIn('fixture',json.dumps(r));self.assertFalse(r['targetInputCheckPassed']);self.assertEqual(m.decode((self.stage/'inputs/package-input.json').read_bytes()),self.original)
  for p in self.draft().iterdir():self.assertEqual(p.stat().st_mode&0o777,0o600)
  self.assertFalse((self.root/'future-data').exists());self.assertFalse((self.root/'future-staging').exists());self.assertIn(b'fixture\\:secret\\\\value', (self.draft()/'onboarding.pass').read_bytes())
 def test_existing_result_is_read_only_no_environment_replay(self):
  first=self.runprep();second=self.runprep(env_reader=lambda _:self.fail('replayed'));self.assertTrue(second.pop('existingResultReadOnly'));self.assertEqual(first,second);self.assertEqual(len(self.reads),4)
 def test_boot_change_holds_before_credentials_and_cannot_replay(self):
  r=self.runprep(boot_reader=lambda:'other');self.assertEqual(r['reason'],'INPUTS_BOOT_CHANGED');self.assertEqual(self.reads,[]);self.assertEqual(self.runprep()['status'],'HELD')
 def test_process_change_during_environment_read_holds(self):
  def drift(pid):v=self.envread(pid);self.pin[self.roster['postgres']['generation']['pid']]=dict(self.pin[self.roster['postgres']['generation']['pid']],startTicks=0);return v
  r=self.runprep(env_reader=drift);self.assertEqual(r['reason'],'INPUTS_POSTGRES_PROCESS_CHANGED');self.assertFalse((self.draft()/'package-input.review.json').exists())
 def test_history_change_denied_before_draft(self):
  Path(self.original['priorReceiptFiles'][0]['path']).write_text('{}')
  with self.assertRaisesRegex(ValueError,'INPUTS_HISTORY_CHANGED'):self.runprep()
  self.assertFalse(self.draft().exists())
 def test_seed_checksum_change_holds_before_environment(self):
  self.profile['seedCanonicalSha256']='0'*64;r=self.runprep();self.assertEqual(r['reason'],'INPUTS_EXACT_HISTORICAL_SEED');self.assertEqual(self.reads,[])
 def test_foreign_database_host_is_not_rewritten_to_local(self):
  self.env[self.roster['udp']['generation']['pid']]['OUF_UDP_DB_URL']='jdbc:postgresql://elsewhere:5432/ouf_udp';r=self.runprep();self.assertNotIn('udp',r['connectionDraftsPrepared']);self.assertIn('INPUTS_POSTGRES_HOST_BINDING',r['missingInputs']);self.assertFalse((self.draft()/'udp.pass').exists())
 def test_credential_query_options_not_silently_dropped(self):
  self.env[self.roster['udp']['generation']['pid']]['OUF_UDP_DB_URL']='jdbc:postgresql://postgres:5432/ouf_udp?password=wrong';r=self.runprep();self.assertIn('INPUTS_JDBC_OPTIONS_REQUIRE_REVIEW',r['missingInputs']);self.assertNotIn('wrong',json.dumps(r))
 def test_datasource_override_remains_missing(self):
  self.env[self.roster['udp']['generation']['pid']]['SPRING_DATASOURCE_PASSWORD']='override';r=self.runprep();self.assertIn('INPUTS_DATASOURCE_OVERRIDE_REQUIRES_REVIEW',r['missingInputs']);self.assertFalse((self.draft()/'udp.pass').exists())
 def test_external_spring_configuration_requires_review(self):
  self.env[self.roster['ingestion']['generation']['pid']]['SPRING_CONFIG_ADDITIONAL_LOCATION']='file:/private/override.yaml';r=self.runprep();self.assertIn('INPUTS_DATASOURCE_OVERRIDE_REQUIRES_REVIEW',r['missingInputs']);self.assertNotIn('ingestion',r['connectionDraftsPrepared'])
 def test_symlink_minio_source_held_without_changing_original(self):
  p=self.minioroot/'run/secrets/secret';p.unlink();p.symlink_to(self.minioroot/'run/secrets/access');r=self.runprep();self.assertNotIn('s3',r['connectionDraftsPrepared']);self.assertTrue(p.is_symlink());self.assertFalse((self.draft()/'s3-secret').exists())
 def test_ambiguous_owner_buckets_not_bound(self):
  self.env[self.roster['udp']['generation']['pid']]['OUF_UDP_LAKE_S3_BUCKET']='different-bucket';r=self.runprep();self.assertIn('INPUTS_OWNER_BUCKET_SELECTION_REQUIRED',r['missingInputs']);self.assertFalse((self.draft()/'runtime.review.json').exists())
 def test_environment_parser_rejects_duplicates_and_truncation(self):
  for raw in [b'A=1\0A=2\0',b'A=1',b'x'*(131073)]:
   with self.assertRaises(ValueError):m.environment(raw)
 def test_partial_directory_is_not_cleaned_or_resumed(self):
  self.draft().mkdir();m.put(self.draft()/'preparation.claim.json',b'{}')
  with self.assertRaisesRegex(ValueError,'INPUTS_PARTIAL_DRAFT_REVIEW_REQUIRED'):self.runprep()
  self.assertTrue((self.draft()/'preparation.claim.json').exists());self.assertEqual(self.reads,[])
if __name__=='__main__':unittest.main()
