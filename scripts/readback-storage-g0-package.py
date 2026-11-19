#!/usr/bin/env python3
"""Offline bounded readback; no extracted code or native providers are executed."""
import argparse,hashlib,io,json,tarfile,zipfile
from pathlib import Path
def require(ok,code):
 if not ok:raise ValueError(code)
def sha(b):return hashlib.sha256(b).hexdigest()
def tar_files(raw,limit):
 files={};total=0
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as t:
  for m in t:
   require(m.isfile() and not m.name.startswith('/') and '..' not in Path(m.name).parts and m.name not in files and m.size<=32<<20,'REGULAR_UNIQUE_TAR_MEMBER');total+=m.size;require(total<=limit,'BOUNDED_TAR');files[m.name]=t.extractfile(m).read()
 return files
def verify(path,expected_sha,expected_bytes,tree):
 raw=path.read_bytes();require(len(raw)==expected_bytes and sha(raw)==expected_sha,'EXACT_ARCHIVE')
 z=zipfile.ZipFile(io.BytesIO(raw));names=z.namelist();require(len(names)==len(set(names)) and all('/' not in n and n not in ('','.','..') for n in names) and sum(x.file_size for x in z.infolist())<=64<<20,'BOUNDED_FLAT_ARCHIVE');files={n:z.read(n) for n in names};checks={}
 for line in files['SHA256SUMS'].decode().splitlines():h,n=line.split('  ',1);require(n not in checks,'UNIQUE_CHECKSUM');checks[n]=h
 require(set(checks)==set(files)-{'SHA256SUMS'} and all(sha(files[n])==h for n,h in checks.items()),'EXACT_CHECKSUM_SET')
 delivery=json.loads(files['delivery.json']);build=json.loads(files['build.json']);require(not tree.get('truncated') and delivery['deployCommit']==build['deployCommit']==tree['sha'],'EXACT_GIT_COMMIT')
 source=tar_files(files['sources.tar.gz'],16<<20);source_hash=json.loads(files['source-sha256.json']);require(set(source)==set(source_hash) and all(sha(v)==source_hash[k] for k,v in source.items()),'SOURCE_CHECKSUM_SET')
 expected={'tools/storage_planning/'+n for n in ['g0_host.py','g0_package.py','g0_database.py','g0_reconciliation.py','inventory_manifest.py']}|{'tools/storage_inventory/'+n for n in ['main.go','main_test.go','g0.go','g0_test.go','g0_native_test.go','go.mod','go.sum']}|{'scripts/package-storage-g0.py','tests/test_storage_g0_package.py','tests/test_storage_g0_database.py','.github/workflows/storage-g0-package.yml','docs/OUF_STORAGE_G0_OPERATOR_PACKAGE_20261105.md','docs/OUF_STORAGE_G0_COLLECTORS_20261105.md','releases/storage-g0-package-profile-20261105.json'}
 require(set(source)==expected,'EXACT_SOURCE_SET');git={x['path']:x['sha'] for x in tree['tree'] if x['type']=='blob'}
 for p,b in source.items():require(hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==git[p],'EXACT_GIT_BLOB')
 package_raw=files['operator-package.tar.gz'];require(len(package_raw)==delivery['packageBytes'] and sha(package_raw)==delivery['packageSha256'],'EXACT_OPERATOR_ARCHIVE');package=tar_files(package_raw,48<<20)
 manifest_raw=package['package-manifest.json'];require(sha(manifest_raw)==delivery['manifestSha256']==build['manifestSha256'],'EXACT_PACKAGE_MANIFEST');manifest=json.loads(manifest_raw)
 require(set(package)==set(manifest['files'])|{'package-manifest.json'} and all(sha(package[n])==h for n,h in manifest['files'].items()),'EXACT_PACKAGE_FILES')
 require(manifest['deployCommit']==tree['sha'] and manifest['runtimeAuthorityIssued'] is False and manifest['targetBindingsPresent'] is False and manifest['targetCommandAuthorized'] is False and delivery['targetCommandAuthorized'] is False and delivery['targetOperations']==0,'NO_TARGET_ADMISSION')
 for p in expected:
  if p.startswith('tools/storage_planning/'):require(package[p]==source[p],'PACKAGED_PYTHON_MATCHES_GIT')
 for target,origin in [('README.md','docs/OUF_STORAGE_G0_OPERATOR_PACKAGE_20261105.md'),('OUF_STORAGE_G0_COLLECTORS_20261105.md','docs/OUF_STORAGE_G0_COLLECTORS_20261105.md'),('component-profile.json','releases/storage-g0-package-profile-20261105.json')]:require(package[target]==source[origin],'PACKAGED_CONTRACT_MATCHES_GIT')
 profile=json.loads(package['component-profile.json']);bindings=json.loads(files['component-bindings.json']);require(len(profile['qualifiedSourceSha256'])==7 and set(bindings)==set(profile['qualifiedSourceSha256']),'SEVEN_QUALIFIED_COMPONENT_BINDINGS')
 for p,h in profile['qualifiedSourceSha256'].items():require(sha(source[p])==h and bindings[p]=={'expected':h,'observed':h},'QUALIFIED_COMPONENT_BYTES_UNCHANGED')
 binary=package['bin/inventory'];require(binary.startswith(b'\x7fELF') and binary[4:6]==b'\x02\x01' and int.from_bytes(binary[18:20],'little')==62 and sha(binary)==build['inventorySha256'],'EXACT_LINUX_AMD64_BINARY');require(build['goVersion']=='go version go1.27.3 linux/amd64','EXACT_GO_TOOLCHAIN')
 scan=json.loads(files['trivy.json']);require(any(Path(x['Target']).name=='inventory' and x.get('Type')=='gobinary' for x in scan.get('Results',[])) and not any(x.get('Vulnerabilities') for x in scan['Results']),'PACKAGED_EXECUTABLE_ZERO_FINDINGS')
 template=json.loads(package['input-template.json']);require(template['operationId'] is None and template['installationRef'] is None and template['collectionDecisionRef'] is None and len(template['roles'])==13 and len(template['priorReceiptFiles'])==17 and all(x['containerId'] is None and x['nativeImage'] is None for x in template['roles'].values()),'TEMPLATE_NOT_TARGET_BINDING')
 host=json.loads(files['native-host.json']);require(host['status']=='PASS_DISPOSABLE_HOST_OBSERVATION_ONLY' and host['requestsReserved']==2*(host['containersObserved']+1) and host['requestsReserved']<=130 and host['engineBytes']<=32<<20 and host['beforeAfterEqual'] and host['stoppedContainerObservedWithoutStarting'] and host['secretValuesRedacted'] and host['mutationPathDeniedBeforeNetwork'] and host['fixtureStarts']==0 and not host['fullS3DbCompositionNativeRerun'] and host['targetOperations']==0,'NATIVE_HOST_ONLY_RESULT')
 require(b'Ran 13 tests' in files['tests.log'] and files['tests.log'].rstrip().endswith(b'OK'),'THIRTEEN_COMPOSITION_TESTS')
 return {'schema':'ouf.storage-g0-package-readback.v1','status':'PASS_OFFLINE_NOT_TARGET_COLLECTION','deployCommit':tree['sha'],'archiveSha256':expected_sha,'archiveBytes':expected_bytes,'members':len(files),'checksums':len(checks),'exactGitSources':len(source),'packageMembers':len(package),'packageSha256':delivery['packageSha256'],'packageBytes':delivery['packageBytes'],'packageManifestSha256':delivery['manifestSha256'],'unitTests':13,'nativeHostEngineGets':host['requestsReserved'],'nativeHostContainers':host['containersObserved'],'targetOperations':0,'g0Complete':False,'acceptanceCreditAdded':0}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('archive',type=Path);p.add_argument('sha256');p.add_argument('bytes',type=int);p.add_argument('tree',type=Path);a=p.parse_args();print(json.dumps(verify(a.archive,a.sha256,a.bytes,json.loads(a.tree.read_text())),indent=2))
