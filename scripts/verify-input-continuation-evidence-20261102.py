#!/usr/bin/env python3
"""Independent verification of corrective evidence; never invokes its target entry."""
import ast,base64,hashlib,json,subprocess,sys,tempfile,xml.etree.ElementTree as ET,zipfile
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[1]
def require(ok,why):
 if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def verify(path,expected,producer):
 with path.open('rb') as f:require(hashlib.file_digest(f,'sha256').hexdigest()==expected,'EXACT_CORRECTIVE_ARTIFACT_REQUIRED')
 with zipfile.ZipFile(path) as z:
  names=z.namelist();require(len(names)==len(set(names)) and all(str(PurePosixPath(n))==n and not n.startswith('/') and '..' not in PurePosixPath(n).parts for n in names),'UNIQUE_SAFE_CORRECTIVE_MEMBERS_REQUIRED')
  require(sum(i.file_size for i in z.infolist())<=8388608,'BOUNDED_CORRECTIVE_EVIDENCE_REQUIRED')
  prefix='input-evidence/' if 'input-evidence/SHA256SUMS' in names else ''
  read=lambda name:z.read(prefix+name)
  sums={}
  for line in read('SHA256SUMS').decode().splitlines():
   digest,name=line.split('  ',1);require(name not in sums,'NO_DUPLICATE_SUBJECT');sums[name]=digest
  inside={n[len(prefix):] for n in names if n.startswith(prefix)} if prefix else set(names)
  require(set(sums)==inside-{'SHA256SUMS','provenance.json'},'COMPLETE_CORRECTIVE_CHECKSUM_CLOSURE_REQUIRED')
  for name,digest in sums.items():require(sha(read(name))==digest,'CORRECTIVE_MEMBER_CHANGED')
  if prefix:
   extras=set(names)-{prefix+n for n in inside};require(extras=={'sw-evaluation/candidate.json','sw-evaluation/native-target-inventory-result.json'},'CLOSED_DIAGNOSTIC_DUPLICATES_REQUIRED')
   for name in extras:require(z.read(name)==read(Path(name).name),'DIAGNOSTIC_DUPLICATE_CHANGED')
  qualification=json.loads(read('qualification.json'));delivery=json.loads(read('inventory-delivery/delivery.json'));native=json.loads(read('native-target-inventory-result.json'))
  require(qualification['status']=='PASS' and qualification['producerSource']==delivery['producerSource']==producer and qualification['targetOperations']==0 and qualification['releaseAdmitted'] is False,'EXACT_QUALIFIED_NOT_TARGET_PRODUCER_REQUIRED')
  require(native['status']=='PASS' and native['realDockerEngineQualified'] and len(native['cases'])==4 and all(c['retainedSnapshotBytesPreserved'] and c['reproducedExactControl15Stop'] and c['tamperedPreviousStopDeniedBeforeEngineAndS3'] for c in native['cases']) and native['thirteenInspectScanReplayed'] is False and native['historicalScopeChecks']=='MODELLED','REAL_ID_ONLY_DOCKER_AND_MODELLED_HISTORY_REQUIRED')
  positive=[c for c in native['cases'] if c['case']!='oversize'];negative=[c for c in native['cases'] if c['case']=='oversize']
  require(len(positive)==3 and all(c['freshMinioInspects']==2 and c['records']==1010 and c['sourceCustodyAdmitted'] is False for c in positive) and len(negative)==1 and negative[0]['unsupportedInputMetadataComplete'] and negative[0]['contentReads']==negative[0]['s3Requests']==0,'THREE_READ_ONLY_CASES_AND_COMPLETE_ZERO_READ_NEGATIVE_CASE_REQUIRED')
  require(delivery['closedSourceCount']==28 and delivery['allPrior24SourcesUnchanged'] and delivery['allPrior26SourcesUnchanged'] and delivery['payloadBytes']<=327680 and delivery['original23SourcesUnchanged'] and delivery['oldScopeRearmed'] is False and delivery['oldReaderReinstalled'] is False and delivery['backendSha256']=='430631fe4dfd1b844229637373ea176c2e84e81e1491919f4a25cc36c68359a8','EXACT_ORIGINAL_READER_AND_CLOSED_DELIVERY_REQUIRED')
  profile=delivery['controlProfile'];require(profile['previousControlAttempts']==15 and profile['previousEngineGets']==50 and profile['maximumEngineGets']==2 and profile['maximumCredentialFiles']==5 and profile['objectBodiesRead']==profile['sqlRequests']==profile['containerLifecycleOperations']==0,'CORRECT_CUMULATIVE_BOUNDED_PROFILE_REQUIRED')
  capsule=read('inventory-delivery/prepare-inputs.py');require(len(capsule)==delivery['capsuleBytes'] and sha(capsule)==delivery['capsuleSha256'],'EXACT_CORRECTIVE_CAPSULE_REQUIRED')
  values={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(capsule).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ['MANIFEST','PAYLOAD']}
  manifest=values['MANIFEST'];sources=json.loads(base64.b64decode(values['PAYLOAD']));require(len(sources)==28 and manifest['sourceRevisionClaim']==producer,'TWENTY_FOUR_PRODUCER_SOURCES_REQUIRED')
  legacy=0
  for name,record in manifest['sources'].items():
   raw=sources[name].encode();require(sha(raw)==record['sha256']==sha((ROOT/record['path']).read_bytes()),'SOURCE_BYTES_DIFFER_FROM_REVIEWED_REPOSITORY')
   if name not in {'tools.storage_migration.target_inventory_inputs','tools.storage_migration.minio_input_observation'}:legacy+=1
  require(legacy==26,'TWENTY_THREE_FROZEN_SOURCES_REQUIRED')
  original=(ROOT/'releases/seaweedfs-inventory-credentials-20261102/prepare-credentials.py').read_text()
  values24={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(original).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='MANIFEST'}
  require(all(manifest['sources'][name]==record for name,record in values24['MANIFEST']['sources'].items()),'ALL_PRIOR_TWENTY_FOUR_SOURCE_RECORDS_UNCHANGED_REQUIRED')
  expected_tail=original[original.index('\ndef require(ok):'):].replace('0<len(raw)<=294912','0<len(raw)<=327680')
  actual_tail=capsule.decode()[capsule.decode().index('\ndef require(ok):'):]
  require(actual_tail==expected_tail and sha(actual_tail.encode())==manifest['loaderTemplateSha256'],'ONLY_EXPLICIT_NEW_LOADER_BYTE_BOUND_MAY_DIFFER')
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'capsule.py';p.write_bytes(capsule);inspected=json.loads(subprocess.check_output([sys.executable,'-I','-B','-S',str(p),'--inspect-source'],timeout=30));require(inspected['sourceCount']==28 and not inspected['runtimeAuthorityIssued'],'SOURCE_INSPECTION_ONLY_REQUIRED')
  reports=[n for n in sums if n.startswith('contract-reports/TEST-') and n.endswith('.xml')];count=0
  for name in reports:
   r=ET.fromstring(read(name));require(all(int(r.attrib[k])==0 for k in ['failures','errors','skipped']),'NO_FAILED_OR_SKIPPED_JAVA_TESTS');count+=int(r.attrib['tests'])
  require(len(reports)==2 and count==12,'TWELVE_ACTUAL_JAVA_TESTS_REQUIRED')
  scan=json.loads(read('trivy-binary.json'));inventory=[r for r in scan['Results'] if r.get('Type')=='gobinary' and r['Target'].endswith('storage-inventory')]
  require(len(inventory)==1 and inventory[0].get('Packages') and not inventory[0].get('Vulnerabilities'),'EXACT_OLD_READER_FRESH_SCAN_ZERO_FINDINGS_REQUIRED')
  require(json.loads(read('root-install-fixture.json'))['originalReaderBytesPreserved'],'ORIGINAL_INSTALLED_READER_PRESERVED_REQUIRED')
  return {'status':'PASS','artifactSha256':expected,'producerSource':producer,'checksumMembers':len(sums),'closedSources':28,'allPrior26SourcesUnchanged':True,'allPrior24SourcesUnchanged':True,'original23SourcesUnchanged':True,'capsuleSha256':delivery['capsuleSha256'],'realDockerEngineQualified':True,'historicalScopeChecks':'MODELLED','freshMinioInspectsPerSuccessfulCase':2,'credentialCases':4,'thirteenInspectScanReplayed':False,'javaTests':count,'exactOldReaderFreshScan':'ZERO_FINDINGS','targetOperations':0,'oldScopeRearmed':False,'publisherVerifiedBySeparateStep':False}
if __name__=='__main__':print(json.dumps(verify(Path(sys.argv[1]),sys.argv[2],sys.argv[3]),indent=2))
