import ast,copy,hashlib,importlib.util,json,os,stat,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('tools/storage_planning/inventory_manifest.py','manifest')
packer=load('scripts/package-storage-offline-plan-20261102.py','packer')
bootstrap=load('tools/storage_planning/offline_bootstrap_20261102.py','bootstrap')
RECEIPT=json.loads((ROOT/'evidence/seaweedfs-private-baseline-target-20261102.json').read_text())
def fixture():
 # Feature choice is synthetic, NOT evidence of which target APIs are unsupported.
 buckets=[]
 for name in ['private-fixture-a','private-fixture-b']:
  f={'bucket':name,**{k:{'status':'PRESENT','value':{}} for k in m.FEATURES}}
  f['policy']={'status':'ABSENT','code':'NoSuchBucketPolicy'};f['publicAccessBlock']={'status':'UNSUPPORTED','code':'NotImplemented'};buckets.append(f)
 rows=[]
 for i in range(120):
  size=1000 if i<119 else 84743
  rows.append({'bucket':buckets[i//60]['bucket'],'key':'private-object-'+str(i),'versionId':None,'isLatest':True,'deleteMarker':False,'size':size,'sha256':None,'metadataSha256':None,'metadata':{'ouf-content-hash':'sha256:'+'a'*64} if i<110 else {},'headMetadata':{'contentLength':size,'contentType':'private-content-type'},'tags':[]})
 return {'schema':'ouf.storage-private-inventory.v1','complete':True,'requests':265,'records':rows,
  'summary':copy.deepcopy(RECEIPT['inventorySummary']),'objectBodiesRead':0,'targetWrites':0,
  'bucketFeaturesInventoried':True,'bucketFeatureValuesComplete':False,'bucketFeatures':buckets,'multipartUploads':[],'writerInventoryComplete':False}
class ManifestTests(unittest.TestCase):
 def test_120_objects_and_10_missing_hashes_are_planned_without_verification(self):
  v=fixture();before=copy.deepcopy(v);private,public=m.compile_plan(v)
  self.assertEqual(v,before);self.assertEqual(len(private['entries']),120);self.assertEqual(public['objectsWithoutAdvertisedHash'],10)
  self.assertEqual(public['objectsRequiringFullBodyVerification'],120);self.assertEqual(public['verifiedBodies'],0)
  self.assertFalse(private['executionEnabled']);self.assertFalse(public['migrationReady'])
  self.assertTrue(all(e['state']=='PLANNED_NOT_COPIED' and e['bodySha256Verified'] is None for e in private['entries']))
 def test_public_summary_contains_no_private_keys_values_policies_or_hash_hints(self):
  v=fixture();v['bucketFeatures'][0]['policy']={'status':'PRESENT','value':{'Policy':'private-policy-sentinel'}}
  v['records'][0]['metadata']['private-metadata']='private-value-sentinel'
  private,public=m.compile_plan(v);raw=json.dumps(public)
  for forbidden in ['private-fixture','private-object','private-content-type','private-policy-sentinel','private-value-sentinel','a'*64]:self.assertNotIn(forbidden,raw)
  self.assertEqual(public['policyDocumentsToTranslate'],1);self.assertIn('private-policy-sentinel',json.dumps(private))
 def test_unsupported_is_not_absent(self):
  _,public=m.compile_plan(fixture());counts=public['bucketFeatureStatusCounts']['publicAccessBlock']
  self.assertEqual(counts,{'PRESENT':0,'ABSENT':0,'UNSUPPORTED':2,'configured':0})
 def test_all_ten_features_are_required_for_each_bucket(self):
  v=fixture();del v['bucketFeatures'][0]['cors']
  with self.assertRaisesRegex(m.PlanError,'COMPLETE_BUCKET_FEATURE_SET_REQUIRED'):m.compile_plan(v)
 def test_changed_summary_is_denied(self):
  for key,value in [('bytesAcrossVersions',203744),('unsupportedBucketFeatures',0),('defaultEncryptedBuckets',False)]:
   v=fixture();v['summary'][key]=value
   with self.assertRaisesRegex(m.PlanError,'RECOMPUTED_INVENTORY_SUMMARY_MISMATCH'):m.compile_plan(v)
 def test_summary_rejects_boolean_integer_equivalence(self):
  v=fixture();v['summary']['versionedRecords']=False
  with self.assertRaises(m.PlanError):m.compile_plan(v)
 def test_incomplete_or_writing_capture_is_denied(self):
  for key,value in [('complete',False),('targetWrites',1),('objectBodiesRead',1),('writerInventoryComplete',True),('requests',True)]:
   v=fixture();v[key]=value
   with self.assertRaises(m.PlanError):m.compile_plan(v)
 def test_duplicate_identity_and_multiple_latest_are_denied(self):
  v=fixture();v['records'][1]=copy.deepcopy(v['records'][0])
  with self.assertRaisesRegex(m.PlanError,'DUPLICATE_SOURCE_OBJECT_VERSION'):m.compile_plan(v)
  v=fixture();v['records'][1].update(key=v['records'][0]['key'],versionId='new-version')
  with self.assertRaisesRegex(m.PlanError,'MULTIPLE_LATEST_SOURCE_VERSIONS'):m.compile_plan(v)
 def test_unlisted_bucket_and_wrong_head_length_are_denied(self):
  for mutate in [lambda v:v['records'][0].update(bucket='not-enumerated'),lambda v:v['records'][0]['headMetadata'].update(contentLength=999)]:
   v=fixture();mutate(v)
   with self.assertRaises(m.PlanError):m.compile_plan(v)
 def test_advertised_bad_hash_is_reported_and_never_trusted(self):
  v=fixture();v['records'][0]['metadata']['ouf-content-hash']='invalid-advertised-hash'
  p,r=m.compile_plan(v);self.assertEqual(r['unrecognizedAdvertisedHashFormats'],1);self.assertFalse(p['entries'][0]['advertisedHashIsVerification'])
 def test_source_cannot_claim_preverified_hashes(self):
  for field in ['sha256','metadataSha256']:
   v=fixture();v['records'][0][field]='sha256:'+'b'*64
   with self.assertRaisesRegex(m.PlanError,'METADATA_CAPTURE_CANNOT_ASSERT_VERIFIED_HASHES'):m.compile_plan(v)
 def test_metadata_tags_and_encryption_retention_are_preserved_privately(self):
  v=fixture();row=v['records'][0];row['tags']=[{'Key':'private-tag','Value':'private-tag-value'}]
  row['headMetadata'].update(serverSideEncryption='aws:kms',kmsKeyId='private-kms',retainUntilDate='2030-01-01',legalHoldStatus='ON',contentEncoding='gzip',cacheControl='private')
  p,r=m.compile_plan(v);self.assertEqual(p['entries'][0]['source'],row)
  self.assertEqual(set(r['objectAttributeCounts'].values()),{1});self.assertNotIn('private-kms',json.dumps(r))
 def test_malformed_metadata_or_tags_denied(self):
  for field,value in [('metadata',[]),('metadata',{'x':1}),('tags',[{'Key':'x','Value':0}])]:
   v=fixture();v['records'][0][field]=value
   with self.assertRaises(m.PlanError):m.compile_plan(v)
 def test_duplicate_json_and_nonfinite_denied(self):
  for raw in ['{"a":1,"a":2}','{"a":NaN}']:
   with self.assertRaises(m.PlanError):m.decode(raw)
 def test_unknown_status_or_unproven_absence_denied(self):
  for entry in [{'status':'UNKNOWN'},{'status':'ABSENT','code':'AccessDenied'},{'status':'UNSUPPORTED','code':'AccessDenied'}]:
   v=fixture();v['bucketFeatures'][0]['cors']=entry
   with self.assertRaises(m.PlanError):m.compile_plan(v)
 def test_compiler_and_target_have_no_network_subprocess_or_credential_imports(self):
  for path in packer.SOURCES:
   t=ast.parse((ROOT/path).read_text())
   imports={n.names[0].name.split('.')[0] for n in ast.walk(t) if isinstance(n,ast.Import)}
   self.assertFalse(imports-{'hashlib','json','re','os','stat','sys','time','resource','signal'})
   self.assertFalse(any(isinstance(n,ast.ImportFrom) and n.module!='pathlib' for n in ast.walk(t)))
 def test_unicode_and_reserved_key_characters_are_preserved_exactly(self):
  v=fixture();v['records'][0]['key']='private/è%2F?&+#';p,r=m.compile_plan(v)
  self.assertEqual(p['entries'][0]['source']['key'],'private/è%2F?&+#');self.assertNotIn('private/',json.dumps(r))
 def test_historical_versions_are_planned_without_inventing_copy_order(self):
  v=fixture();v['records'][0]['versionId']='opaque-v1';v['records'][1].update(key=v['records'][0]['key'],versionId='opaque-v0',isLatest=False);v['summary']['versionedRecords']=2
  p,r=m.compile_plan(v);self.assertEqual(p['entries'][1]['source']['versionId'],'opaque-v0');self.assertFalse(r['historicalVersionCopyOrderProven'])
 def test_delete_marker_kept_without_body_claim(self):
  v=fixture();v['records'][119].update(versionId='opaque-marker',deleteMarker=True,size=0);v['summary'].update(objectVersions=119,deleteMarkers=1,versionedRecords=1,bytesAcrossVersions=119000)
  p,r=m.compile_plan(v);self.assertEqual(r['objectsRequiringFullBodyVerification'],119);self.assertEqual(p['entries'][119]['requirements'],['PRESERVE_DELETE_MARKER_HISTORY'])
 def test_unsafe_namespace_remains_held_with_private_plan(self):
  v=fixture();v['records'][0]['key']='../unsafe';v['summary'].update(unsafePathKeys=1,namespaceGate='HELD')
  p,r=m.compile_plan(v);self.assertEqual(r['sourceSummary']['namespaceGate'],'HELD');self.assertFalse(r['migrationReady']);self.assertFalse(p['executionEnabled'])
class RootArtifactsTests(unittest.TestCase):
 def setUp(self):
  self.assertEqual(os.geteuid(),0)
  parent='/root' if os.environ.get('GITHUB_ACTIONS')=='true' else ROOT
  self.tmp=tempfile.TemporaryDirectory(dir=parent);self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);self.root.chmod(0o700);self.input=self.root/'input16';self.input.mkdir(mode=0o700);(self.input/'s3').mkdir(mode=0o700)
  self.scope=self.root/'plan17';self.scope.mkdir(mode=0o700)
  body,_=packer.build(RECEIPT);self.module={'__name__':'synthetic_bound_fixture'};exec(compile(body,'qualified-offline-compiler','exec'),self.module)
  self.host={'bindings':[{'role':role,'storageBindingValues':({'OUF_UDP_S3_ENDPOINT':'http://private-endpoint-sentinel'} if role=='udp' else {})} for role in sorted(m.PUBLIC_ROLES)],'pointInTimeSnapshotProven':False,'externalConsumersProvenAbsent':False};self.host_path=self.root/'host14.json';self.host_path.write_bytes(m.canonical(self.host));self.host_path.chmod(0o600)
  self.v=fixture();self.raw=m.canonical(self.v);self.receipt={k:v for k,v in RECEIPT.items() if not k.startswith('inventoryReconciliation')};self.receipt['privateInventorySha256']=m.sha(self.raw);self.receipt['retainedHostBaselineHash']=m.sha(m.canonical(self.host))
  for name,value in [('capture.claim.json',{'schema':'ouf.m2-discovery-custody-capture-claim.v1','automaticReplayAllowed':False}),('result.json',self.receipt),('s3/inventory.private.json',self.v)]:
   p=self.input/name;p.write_bytes(m.canonical(value));p.chmod(0o600)
  self.module.update(INPUT=self.input,SCOPE=self.scope,HOST=self.host_path,HOST_SHA=m.sha(m.canonical(self.host)),INVENTORY_SHA=m.sha(self.raw),EXPECTED_RECEIPT=self.receipt)
 def collect(self):return self.module['collect_plan'](self.module['OfflineFiles']())
 def test_root_filesystem_positive_retained_bytes_and_modes_unchanged(self):
  before={str(p):p.read_bytes() for p in self.input.rglob('*') if p.is_file()};r=self.collect()
  self.assertEqual(r['cumulativeControlAttempts'],17);self.assertEqual(r['cumulativeDirectEngineGets'],52);self.assertEqual(r['privateMetadataFilesOpened'],4)
  self.assertTrue(r['control16EvidenceStableDuringAnalysis']);self.assertEqual(r['credentialFilesOpened'],0)
  self.assertEqual(before,{str(p):p.read_bytes() for p in self.input.rglob('*') if p.is_file()})
  p=self.scope/'migration-plan.private.json';self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
  self.assertEqual(m.sha(p.read_bytes()),r['privatePlanSha256'])
 def test_retained_host_binding_summary_is_redacted_and_not_fresh_writer_proof(self):
  r=self.collect();self.assertEqual(r['configuredStorageRolesAtControl14'],['udp']);self.assertFalse(r['activeWritersProven']);self.assertNotIn('private-endpoint-sentinel',json.dumps(r))
 def test_tampered_host_hash_denied_without_inventory_read(self):
  self.host_path.write_bytes(b'{}');c=self.module['OfflineFiles']()
  with self.assertRaisesRegex(ValueError,'EXACT_RETAINED_HOST_HASH_REQUIRED'):self.module['collect_plan'](c)
  self.assertEqual(c.opened,3)
 def test_tampered_inventory_hash_denied_before_plan_output(self):
  p=self.input/'s3/inventory.private.json';p.write_bytes(self.raw+b' ')
  with self.assertRaisesRegex(ValueError,'EXACT_PRIVATE_INVENTORY_HASH_REQUIRED'):self.collect()
  self.assertFalse((self.scope/'migration-plan.private.json').exists())
 def test_tampered_receipt_denied_before_inventory_open(self):
  p=self.input/'result.json';p.write_bytes(m.canonical({**self.receipt,'records':119}));c=self.module['OfflineFiles']()
  with self.assertRaisesRegex(ValueError,'EXACT_COMPLETE_CONTROL16_RECEIPT_REQUIRED'):self.module['collect_plan'](c)
  self.assertEqual(c.opened,2)
 def test_inventory_symlink_and_fifo_are_denied_without_content_reads(self):
  p=self.input/'s3/inventory.private.json';p.unlink();p.symlink_to(self.input/'result.json')
  with self.assertRaises(OSError):self.collect()
  p.unlink();os.mkfifo(p,0o600)
  with self.assertRaisesRegex(ValueError,'PRIVATE_REGULAR_METADATA_ARTIFACT_REQUIRED'):self.collect()
 def test_nonprivate_artifact_and_hardlink_denied(self):
  p=self.input/'s3/inventory.private.json';p.chmod(0o644)
  with self.assertRaises(ValueError):self.collect()
  p.chmod(0o600);os.link(p,self.root/'extra-link')
  with self.assertRaises(ValueError):self.collect()
 def test_metadata_change_after_read_is_denied(self):
  c=self.module['OfflineFiles']();c.read(self.input/'result.json',32768);(self.input/'result.json').write_bytes(b'{}')
  with self.assertRaisesRegex(ValueError,'RETAINED_METADATA_ARTIFACTS_CHANGED'):c.stable()
 def test_plan_output_cannot_be_overwritten(self):
  self.collect();p=self.scope/'migration-plan.private.json';before=p.read_bytes()
  with self.assertRaises(FileExistsError):self.collect()
  self.assertEqual(p.read_bytes(),before)
 def test_credential_related_file_contents_are_never_opened(self):
  # A FIFO would hang a content read; it must remain completely unvisited.
  os.mkfifo(self.input/'inventory-config.private.json',0o600);r=self.collect();self.assertEqual(r['privateMetadataFilesOpened'],4)
 def test_root_installer_rejects_wrong_bytes_and_existing_install(self):
  delivery={'sourceCount':2,'controlAttempt':17,'previousControlAttempts':16,'previousEngineGets':52,'newEngineGets':0,'newS3Requests':0,'credentialFileReads':0,'objectBodiesRead':0,'oldScopeRearmed':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'scopePath':str(bootstrap.SCOPE),'installPath':str(bootstrap.INSTALL),'capsuleBytes':8,'capsuleSha256':m.sha(b'exact123')}
  with patch.object(bootstrap,'DELIVERY',delivery),patch.object(bootstrap,'PUBLICATION','a'*40):
   bootstrap.validate()
   with self.assertRaisesRegex(ValueError,'EXACT_OFFLINE_COMPILER_BYTES_REQUIRED'):bootstrap.install(b'wrong123')
 def test_root_install_contains_only_exact_compiler_and_manifest(self):
  raw=b'exact123';target=self.root/'install'
  with patch.object(bootstrap,'DELIVERY',{'capsuleBytes':len(raw),'capsuleSha256':m.sha(raw)}),patch.object(bootstrap,'INSTALL',target):
   bootstrap.install(raw);self.assertEqual(set(p.name for p in target.iterdir()),{'prepare-plan.py','delivery.json'})
   self.assertEqual((target/'prepare-plan.py').read_bytes(),raw);self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o500)
   self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o400 for p in target.iterdir()))
   with self.assertRaises(ValueError):bootstrap.install(raw)
   target.chmod(0o700)
 def test_root_delivery_profile_cannot_enable_network_or_reuse_scopes(self):
  with patch.object(bootstrap,'DELIVERY',{'sourceCount':2,'controlAttempt':17,'previousControlAttempts':16,'previousEngineGets':52,'newEngineGets':1,'newS3Requests':0,'credentialFileReads':0,'objectBodiesRead':0,'oldScopeRearmed':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False} ),patch.object(bootstrap,'PUBLICATION','a'*40):
   with self.assertRaises(ValueError):bootstrap.validate()
if __name__=='__main__':unittest.main()
