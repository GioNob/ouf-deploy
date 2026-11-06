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
def verify(path,expected_sha,expected_bytes,trees):
 tree=trees["deploy"]
 raw=path.read_bytes();require(len(raw)==expected_bytes and sha(raw)==expected_sha,'EXACT_ARCHIVE')
 z=zipfile.ZipFile(io.BytesIO(raw));names=z.namelist();require(len(names)==len(set(names)) and all('/' not in n and n not in ('','.','..') for n in names) and sum(x.file_size for x in z.infolist())<=64<<20,'BOUNDED_FLAT_ARCHIVE');files={n:z.read(n) for n in names};checks={}
 for line in files['SHA256SUMS'].decode().splitlines():h,n=line.split('  ',1);require(n not in checks,'UNIQUE_CHECKSUM');checks[n]=h
 require(set(checks)==set(files)-{'SHA256SUMS'} and all(sha(files[n])==h for n,h in checks.items()),'EXACT_CHECKSUM_SET')
 delivery=json.loads(files['delivery.json']);build=json.loads(files['build.json']);require(not tree.get('truncated') and delivery['deployCommit']==build['deployCommit']==tree['sha'],'EXACT_GIT_COMMIT')
 source=tar_files(files['sources.tar.gz'],16<<20);source_hash=json.loads(files['source-sha256.json']);require(set(source)==set(source_hash) and all(sha(v)==source_hash[k] for k,v in source.items()),'SOURCE_CHECKSUM_SET')
 expected={'tools/storage_planning/'+n for n in ['g0_host.py','g0_package.py','g0_database.py','g0_reconciliation.py','inventory_manifest.py']}|{'tools/storage_inventory/'+n for n in ['main.go','main_test.go','g0.go','g0_test.go','g0_native_test.go','go.mod','go.sum']}|{'scripts/package-storage-g0.py','tests/test_storage_g0_package.py','tests/test_storage_g0_database.py','.github/workflows/storage-g0-package.yml','docs/OUF_STORAGE_G0_OPERATOR_PACKAGE_20261105.md','docs/OUF_STORAGE_G0_COLLECTORS_20261105.md','releases/storage-g0-package-profile-20261105.json'}
 expected |= {'tools/storage_planning/g0_network.py','scripts/qualify-storage-g0-network-20261106.py','tests/test_storage_g0_network.py','tests/fixtures/storage-g0-network/seed_test.go','tests/fixtures/storage-g0-db/seed.sql','docs/OUF_STORAGE_G0_NETWORK_20261106.md'}
 commits=json.loads(files['source-commits.json']);require(commits=={'deploy':tree['sha'],'ouf-source-onboarding':'d5155899b09dda298494b68cefa7e1f281167652','ouf-udp-object-resolution':'0d40da05408a14db31d4d41af2372d6a71480291','ouf-ingestion-runtime':'4165b9e149be467d5d7c6bed35e4e1af4e249db1'},'EXACT_FOUR_COMMITS')
 git={x['path']:x['sha'] for x in tree['tree'] if x['type']=='blob'}
 for repo,t in trees.items():
  if repo=='deploy':continue
  require(not t.get('truncated') and t['sha']==commits[repo],'EXACT_APPLICATION_COMMIT')
  for x in t['tree']:
   if x['type']=='blob' and x['path'].startswith('src/main/resources/db/migration/V') and x['path'].endswith('.sql'):
    name=repo+'/'+x['path'];expected.add(name);git[name]=x['sha']
 require(set(source)==expected and len(source)==120,'EXACT_SOURCE_SET')
 for p,b in source.items():require(hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==git[p],'EXACT_GIT_BLOB')
 package_raw=files['operator-package.tar.gz'];require(len(package_raw)==delivery['packageBytes'] and sha(package_raw)==delivery['packageSha256'],'EXACT_OPERATOR_ARCHIVE');package=tar_files(package_raw,48<<20)
 require(set(package)=={'package-manifest.json','bin/inventory','launch.py','network-worker.py','input-template.json','README.md','HOST_PROFILE.md','OUF_STORAGE_G0_COLLECTORS_20261105.md','component-profile.json'}|{'tools/storage_planning/'+n for n in ['g0_host.py','g0_package.py','g0_network.py','g0_database.py','g0_reconciliation.py','inventory_manifest.py']},'EXACT_FIFTEEN_PACKAGE_MEMBERS')
 manifest_raw=package['package-manifest.json'];require(sha(manifest_raw)==delivery['manifestSha256']==build['manifestSha256'],'EXACT_PACKAGE_MANIFEST');manifest=json.loads(manifest_raw)
 require(set(package)==set(manifest['files'])|{'package-manifest.json'} and all(sha(package[n])==h for n,h in manifest['files'].items()),'EXACT_PACKAGE_FILES')
 require(manifest['deployCommit']==tree['sha'] and manifest['runtimeAuthorityIssued'] is False and manifest['targetBindingsPresent'] is False and manifest['targetCommandAuthorized'] is False and delivery['targetCommandAuthorized'] is False and delivery['targetOperations']==0,'NO_TARGET_ADMISSION')
 for p in expected:
  if p.startswith('tools/storage_planning/'):require(package[p]==source[p],'PACKAGED_PYTHON_MATCHES_GIT')
 for target,origin in [('README.md','docs/OUF_STORAGE_G0_NETWORK_20261106.md'),('HOST_PROFILE.md','docs/OUF_STORAGE_G0_OPERATOR_PACKAGE_20261105.md'),('OUF_STORAGE_G0_COLLECTORS_20261105.md','docs/OUF_STORAGE_G0_COLLECTORS_20261105.md'),('component-profile.json','releases/storage-g0-package-profile-20261105.json')]:require(package[target]==source[origin],'PACKAGED_CONTRACT_MATCHES_GIT')
 profile=json.loads(package['component-profile.json']);bindings=json.loads(files['component-bindings.json']);require(len(profile['qualifiedSourceSha256'])==7 and set(bindings)==set(profile['qualifiedSourceSha256']),'SEVEN_QUALIFIED_COMPONENT_BINDINGS')
 for p,h in profile['qualifiedSourceSha256'].items():require(sha(source[p])==h and bindings[p]=={'expected':h,'observed':h},'QUALIFIED_COMPONENT_BYTES_UNCHANGED')
 binary=package['bin/inventory'];require(binary.startswith(b'\x7fELF') and binary[4:6]==b'\x02\x01' and int.from_bytes(binary[18:20],'little')==62 and sha(binary)==build['inventorySha256'],'EXACT_LINUX_AMD64_BINARY');require(build['goVersion']=='go version go1.27.3 linux/amd64','EXACT_GO_TOOLCHAIN')
 scan_hash=json.loads(files['scan-executables.json']);require(set(scan_hash)=={'inventory','seed.test'} and scan_hash['inventory']==sha(binary),'SCANNED_COLLECTOR_BYTES')
 for report,target in [('trivy.json','inventory'),('trivy-fixture.json','seed.test')]:
  scan=json.loads(files[report]);require(any(Path(x['Target']).name==target and x.get('Type')=='gobinary' for x in scan.get('Results',[])) and not any(x.get('Vulnerabilities') for x in scan['Results']),'BOTH_EXECUTABLES_ZERO_FINDINGS')
 for name,module,call in [('launch.py','g0_package','main'),('network-worker.py','g0_network','worker_main')]:
  expected_launcher=f"import sys\nfrom pathlib import Path\nroot=Path(__file__).resolve().parent\nsys.path.insert(0,str(root))\nfrom tools.storage_planning.{module} import {call}\nraise SystemExit({call}(root))\n".encode();require(package[name]==expected_launcher,'EXACT_GENERATED_LAUNCHER')
 template=json.loads(package['input-template.json']);require(template['operationId'] is None and template['installationRef'] is None and template['collectionDecisionRef'] is None and len(template['roles'])==13 and len(template['priorReceiptFiles'])==17 and all(x['containerId'] is None and x['nativeImage'] is None for x in template['roles'].values()),'TEMPLATE_NOT_TARGET_BINDING')
 require(template['schema']=='ouf.storage-g0-package-input.v2' and template['networkBindingFile']=='/var/lib/ouf/g0/inputs/network.json','EXPLICIT_NETWORK_TEMPLATE')
 for log,count in [('tests.log',13),('network-tests.log',14)]:require(('Ran '+str(count)+' tests').encode() in files[log] and files[log].rstrip().endswith(b'OK') and b'skipped' not in files[log],'ALL_TESTS_EXECUTED')
 n=json.loads(files['native-network.json']);require(n['status']=='PASS_DISTINCT_NATIVE_NAMESPACES_NOT_TARGET_ACCEPTANCE' and n['migrationsApplied']=={'onboarding':41,'udp':36,'ingestion':18} and n['conditionalBodies']==2 and n['conditionalBytes']==6 and n['namespaceChildren']==4 and n['publishedPorts']==0 and n['currentOwnerProfiles']==3 and n['stoppedOtherRoleFixtures']==11,'EXACT_NATIVE_COMPOSITION')
 for key in ('providersInDistinctNetworks','parentNetworkAndMountPreserved','wrongNetworkFdDeniedBeforeCollector','deadOwnerDeniedWhileFdHeld','sameOperationReplayDenied','priorReceiptsUnchanged','newNamespaceCompositionNative'):require(n[key] is True,'NATIVE_POSITIVE_AND_DENIALS')
 for key in ('runtimeAuthorityIssued','fullApplicationServicesQualified','postgresRemoteTlsQualified'):require(n[key] is False,'NO_NATIVE_OVERCLAIM')
 require(n['targetOperations']==n['acceptanceCreditAdded']==0,'NO_ACCEPTANCE_CREDIT')
 r=json.loads(files['network-package-result.json']);require(r['technicalCaptureComplete'] and r['status']=='OBSERVATIONS_SEALED_G0_REVIEW_REQUIRED' and r['sections']['OBJECTS']['verifiedBodies']==2 and r['sections']['DB']['findings']==0 and r['databaseExportsAttempted']==3 and r['engineGets']==28 and r['cumulativeEngineGets']==80 and not r['g0Complete'] and not r['runtimeAuthorityIssued'],'COMPLETE_BOUNDED_CAPTURE')
 entries=[json.loads(v) for k,v in files.items() if k.startswith('network-entry-')];require(len(entries)==4 and sorted(x['role'] for x in entries)==['minio','postgres','postgres','postgres'],'FOUR_CORRECT_ROLES')
 require(len({tuple(e['enteredNet']) for e in entries})==2 and len({tuple(e['previousNet']) for e in entries})==1 and len({e['bindingSha256'] for e in entries})==1 and all(e['enteredNet']==e['ownerProcess']['namespaces']['net'] and e['enteredNet']!=e['previousNet'] and e['mountNamespaceUnchanged'] and not e['runtimeAuthorityIssued'] for e in entries),'TWO_PRIVATE_NETWORKS_HOST_PRESERVED')
 exits=json.loads(files['network-fixture-exits.json']);require(len(exits)==13 and all(e=={'exitCode':0,'oomKilled':False,'running':False} for e in exits.values()),'THIRTEEN_CLEAN_FIXTURE_EXITS')
 summaries={k:json.loads(v) for k,v in files.items() if k.endswith('-summary.json')};require(len(summaries)==4 and all(v['complete'] for v in summaries.values()),'FOUR_COMPLETE_CHILDREN')
 return {'schema':'ouf.storage-g0-network-readback.v1','status':'PASS_OFFLINE_NOT_TARGET_COLLECTION','deployCommit':tree['sha'],'archiveSha256':expected_sha,'archiveBytes':expected_bytes,'members':len(files),'checksums':len(checks),'exactGitSources':len(source),'packageMembers':len(package),'packageSha256':delivery['packageSha256'],'packageBytes':delivery['packageBytes'],'packageManifestSha256':delivery['manifestSha256'],'compositionTests':13,'networkTests':14,'namespaceChildren':4,'nativeEngineGets':28,'nativeCumulativeEngineGets':80,'syntheticBodies':2,'databaseProfiles':3,'targetOperations':0,'g0Complete':False,'acceptanceCreditAdded':0}

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('archive',type=Path);p.add_argument('sha256');p.add_argument('bytes',type=int);p.add_argument('tree',type=Path);a=p.parse_args();print(json.dumps(verify(a.archive,a.sha256,a.bytes,json.loads(a.tree.read_text())),indent=2))
