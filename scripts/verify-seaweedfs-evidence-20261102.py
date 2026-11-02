#!/usr/bin/env python3
"""Independent byte readback, not a release/target admission."""
import argparse,hashlib,io,json
from pathlib import Path,PurePosixPath
import tarfile
import xml.etree.ElementTree as ET
import zipfile

ROOT=Path(__file__).resolve().parents[1]
def require(ok,why):
 if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def verify(path,expected,java_tests=7,record_count=1009,delivery=False):
 with path.open('rb') as f:require(hashlib.file_digest(f,'sha256').hexdigest()==expected,'EXACT_ARTIFACT_ZIP_REQUIRED')
 with zipfile.ZipFile(path) as z:
  names=z.namelist();require(len(names)==len(set(names)) and all(str(PurePosixPath(n))==n and not n.startswith('/') and '..' not in PurePosixPath(n).parts for n in names),'UNIQUE_SAFE_ARCHIVE_MEMBERS_REQUIRED')
  require(sum(i.file_size for i in z.infolist())<=2*1024**3,'UNCOMPRESSED_ARTIFACT_BUDGET')
  sums={}
  for line in z.read('SHA256SUMS').decode().splitlines():
   digest,name=line.split('  ',1);require(name not in sums,'DUPLICATE_CHECKSUM_SUBJECT');sums[name]=digest
  require(set(sums)==set(names)-{'SHA256SUMS','provenance.json'},'COMPLETE_CHECKSUM_CLOSURE_REQUIRED')
  for name,expected_digest in sums.items():require(sha(z.read(name))==expected_digest,'MEMBER_DIGEST_MISMATCH')
  tree=json.loads((ROOT/'releases/seaweedfs-upstream-source-tree-20261102.json').read_text());files={f['path']:f for f in tree['files']};seen=set()
  with tarfile.open(fileobj=io.BytesIO(z.read('source.tar'))) as t:
   for m in t:
    if m.isdir():continue
    require(m.name in files and m.name not in seen,'SOURCE_TREE_EXTRA_OR_DUPLICATE')
    f=files[m.name];require(m.isfile() or m.issym(),'SOURCE_MEMBER_TYPE_DENIED')
    if m.issym():require(f['mode']=='120000','SOURCE_SYMLINK_MODE');raw=m.linkname.encode()
    else:
     require(bool(m.mode&0o111)==(f['mode']=='100755'),'SOURCE_EXECUTABLE_MODE')
     raw=t.extractfile(m).read()
    blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+bytes([0])+raw).hexdigest();require(blob==f['sha'],'SOURCE_GIT_BLOB_MISMATCH');seen.add(m.name)
  require(seen==set(files),'COMPLETE_UPSTREAM_SOURCE_TREE_REQUIRED')
  candidate=json.loads(z.read('candidate.json'));require(sha(z.read('bin/weed'))==candidate['binarySha256'],'ACTUAL_TESTED_BINARY_REQUIRED')
  require(candidate['declaredSource']==tree['commit'] and candidate['cgoEnabled'] is False and candidate['buildToolchain']=='go1.27.3','EXACT_PATCHED_BUILD_PROFILE_REQUIRED')
  require(sha(z.read('dependency.patch'))=='e00e55e9210cc931e985ae218be39650fe403d6ac6568f046e9bb46077c47820','ONLY_EVALUATED_DEPENDENCY_PATCH_REQUIRED')
  packages=json.loads(z.read('compiled-packages.json'))['packages'];require(len(packages)==1738 and not any(p=='golang.org/x/crypto/openpgp' or p.startswith('golang.org/x/crypto/openpgp/') for p in packages),'EXACT_OPENPGP_APPLICABILITY_GRAPH_REQUIRED')
  reports=[n for n in names if n.startswith('contract-reports/TEST-') and n.endswith('.xml')];require(len(reports)==2,'TWO_REAL_CONTRACT_REPORTS_REQUIRED');count=0
  for name in reports:
   r=ET.fromstring(z.read(name));require(all(int(r.attrib.get(k,-1))==0 for k in ['failures','errors','skipped']),'NO_FAILURE_ERROR_SKIP');count+=int(r.attrib['tests'])
  require(count==java_tests,'COMPLETE_ACTUAL_JAVA_TEST_SET_REQUIRED')
  contract=json.loads(z.read('contract-result.json'));inventory=json.loads(z.read('inventory-live-result.json'))
  require(contract['status']=='PASS' and contract['coldRestoreOnIndependentCopy'] is True and not contract['targetE2E'],'ISOLATED_COLD_RESTORE_REQUIRED')
  require(inventory['status']=='PASS' and inventory['syntheticRecords']==record_count and inventory['automaticReplayDenied'] and inventory['bucketFeatureInventoryComplete'],'COMPLETE_SYNTHETIC_INVENTORY_REQUIRED')
  report=json.loads(z.read('trivy-binary.json'));require(report['Trivy']['Version']=='0.70.0','PINNED_SCANNER_REQUIRED')
  scans=[r for r in report['Results'] if r.get('Type')=='gobinary'];require(len(scans)==2 and all(r.get('Packages') for r in scans),'TWO_EXECUTABLE_PACKAGE_INVENTORIES_REQUIRED')
  findings=[v for r in scans for v in r.get('Vulnerabilities') or []]
  require(len(findings)==1 and findings[0]['VulnerabilityID']=='GO-2026-5932' and findings[0]['Severity']=='UNKNOWN','UNCHANGED_RAW_UNKNOWN_MUST_REMAIN_VISIBLE')
  inventory_scan=[r for r in scans if r['Target'].endswith('storage-inventory')];require(len(inventory_scan)==1 and not inventory_scan[0].get('Vulnerabilities'),'CLEAN_INVENTORY_EXECUTABLE_REQUIRED')
  delivery_result = {}
  if delivery:
   import ast,base64,gzip,subprocess,sys,tempfile
   d=json.loads(z.read('inventory-delivery/delivery.json'));require(d['closedSourceCount']==24 and d['original23SourcesUnchanged'] and d['capsuleTamperDenied'],'CLOSED_TAMPER_CHECKED_DELIVERY_REQUIRED')
   require(d['backendSha256']==sha(z.read('bin/storage-inventory')) and d['backendInstallPath']=='/usr/local/lib/ouf-storage-inventory-20261102/inventory' and d['scopePath']=='/etc/ouf/deploy-snapshots/seaweedfs-inventory-20261102-v1','EXACT_BACKEND_AND_SCOPE_BINDING_REQUIRED')
   compressed=bytearray()
   for part in d['parts']:
    raw=z.read('inventory-delivery/'+part['name']);require(len(raw)==part['bytes'] and sha(raw)==part['sha256'],'DELIVERY_PART_CHANGED');compressed.extend(raw)
   require(len(compressed)==d['compressedBackendBytes'] and sha(compressed)==d['compressedBackendSha256'] and gzip.decompress(compressed)==z.read('bin/storage-inventory'),'EXACT_REASSEMBLED_EXECUTABLE_REQUIRED')
   capsule=z.read('inventory-delivery/prepare-storage-inventory.py');require(sha(capsule)==d['capsuleSha256'],'EXACT_CAPSULE_REQUIRED')
   values={}
   for node in ast.parse(capsule).body:
    if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ['MANIFEST','PAYLOAD']:values[node.targets[0].id]=ast.literal_eval(node.value)
   manifest=values['MANIFEST'];sources=json.loads(base64.b64decode(values['PAYLOAD']));require(len(sources)==24,'TWENTY_FOUR_CLOSED_SOURCES_REQUIRED')
   legacy=0
   for name,record in manifest['sources'].items():
    require(sha(sources[name].encode())==record['sha256'],'CAPSULE_SOURCE_CHANGED')
    if name!='tools.storage_migration.target_inventory':require(sha((ROOT/record['path']).read_bytes())==record['sha256'],'FROZEN_SOURCE_CHANGED');legacy+=1
   require(legacy==23,'ALL_TWENTY_THREE_HISTORICAL_SOURCES_REQUIRED')
   with tempfile.TemporaryDirectory(prefix='ouf-sw-readback-') as tmp:
    p=Path(tmp)/'capsule.py';p.write_bytes(capsule)
    inspected=json.loads(subprocess.check_output([sys.executable,'-I','-B','-S',str(p),'--inspect-source'],timeout=60));require(inspected['sourceCount']==24 and not inspected['runtimeAuthorityIssued'],'INSPECT_ONLY_SOURCE_CHECK_REQUIRED')
   delivery_result={'deliverySource':d['producerSource'],'capsuleSha256':d['capsuleSha256'],'closedSources':24,'original23SourcesPreserved':True,'deliveryParts':len(d['parts']),'compressedBackendBytes':d['compressedBackendBytes']}
  return {'schema':'ouf.seaweedfs-independent-byte-readback.v1','delivery':delivery_result,'artifactSha256':expected,'checksumMembers':len(sums),'upstreamGitBlobsAndModes':len(seen),'compiledPackages':len(packages),'javaTests':count,'inventoryRecords':record_count,'inventoryBinarySha256':sha(z.read('bin/storage-inventory')),'rawServerSecurityGate':'HELD_ONE_UNKNOWN','inventoryExecutableScan':'ZERO_FINDINGS','publisherSignatureIndependentlyVerified':False,'releaseAdmitted':False,'targetOperations':0}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('zip',type=Path);p.add_argument('sha256');p.add_argument('--java-tests',type=int,default=7);p.add_argument('--records',type=int,default=1009);p.add_argument('--delivery',action='store_true');a=p.parse_args();print(json.dumps(verify(a.zip,a.sha256,a.java_tests,a.records,a.delivery),indent=2))
