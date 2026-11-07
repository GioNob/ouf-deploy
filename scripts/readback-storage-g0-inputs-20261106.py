#!/usr/bin/env python3
"""Bounded offline source/receipt verification; never executes packaged code."""
import argparse,hashlib,io,json,tarfile,zipfile
from pathlib import Path
def require(ok,code):
 if not ok:raise ValueError(code)
def sha(b):return hashlib.sha256(b).hexdigest()
def untar(b):
 result={};total=0
 with tarfile.open(fileobj=io.BytesIO(b),mode='r:gz') as t:
  for x in t:
   require(x.isfile() and not x.name.startswith('/') and '..' not in Path(x.name).parts and x.name not in result and 0<x.size<=1<<20,'SAFE_TAR_MEMBERS');total+=x.size;require(total<=4<<20,'BOUNDED_TAR');result[x.name]=t.extractfile(x).read()
 return result
def verify(path,expected_sha,expected_bytes,tree):
 raw=path.read_bytes();require(len(raw)==expected_bytes and sha(raw)==expected_sha,'EXACT_ARCHIVE')
 with zipfile.ZipFile(io.BytesIO(raw)) as z:
  names=z.namelist();require(len(names)==len(set(names))==6 and sum(x.file_size for x in z.infolist())<=4<<20,'BOUNDED_ZIP');files={n:z.read(n) for n in names}
 require(set(files)=={'SHA256SUMS','delivery.json','input-tools.tar.gz','sources.tar.gz','source-sha256.json','tests.log'},'EXACT_ARCHIVE_SET')
 checks={}
 for line in files['SHA256SUMS'].decode().splitlines():h,n=line.split('  ',1);require(n not in checks,'UNIQUE_CHECKSUM');checks[n]=h
 require(set(checks)==set(files)-{'SHA256SUMS'} and all(sha(files[n])==h for n,h in checks.items()),'CHECKSUM_SET')
 delivery=json.loads(files['delivery.json']);require(not tree.get('truncated') and delivery['deployCommit']==tree['sha'],'EXACT_COMMIT')
 require(delivery['providerRequests']==delivery['acceptanceCreditAdded']==0 and delivery['runtimeAuthorityIssued'] is False and delivery['targetInputCheckPassed'] is False,'NO_PROVIDER_OR_ACCEPTANCE')
 package=untar(files['input-tools.tar.gz']);require(len(files['input-tools.tar.gz'])==delivery['packageBytes'] and sha(files['input-tools.tar.gz'])==delivery['packageSha256'],'EXACT_PACKAGE')
 mr=package['tool-manifest.json'];require(sha(mr)==delivery['manifestSha256'],'EXACT_MANIFEST');manifest=json.loads(mr)
 require(manifest['deployCommit']==tree['sha'] and manifest['tests']==delivery['tests']==14 and manifest['nativeProviderQualification'] is False and manifest['runtimeAuthorityIssued'] is False,'BOUNDED_QUALIFICATION_SCOPE')
 expected={'tools/storage_planning/g0_input_draft.py','tools/storage_migration/minio_input_observation.py','tools/storage_migration/minio_credential_binding.py','tools/m2_discovery_installation_profile/custody_capture.py','scripts/prepare-storage-g0-inputs-20261106.py','releases/storage-g0-input-preparation-profile-20261106.json','docs/OUF_STORAGE_G0_INPUT_PREPARATION_20261106.md'}
 require(set(package)==expected|{'tool-manifest.json'} and set(manifest['files'])==expected and all(sha(package[p])==h for p,h in manifest['files'].items()),'EXACT_SEVEN_SOURCE_PACKAGE')
 source=untar(files['sources.tar.gz']);hashes=json.loads(files['source-sha256.json']);expected_sources=expected|{'tools/m2_discovery_installation_profile/retained_mount_role_correction.py','scripts/package-storage-g0-inputs-20261106.py','tests/test_storage_g0_input_draft.py','.github/workflows/storage-g0-input-preparation.yml'}
 require(set(source)==set(hashes)==expected_sources and all(sha(source[p])==h for p,h in hashes.items()),'EXACT_ELEVEN_SOURCES');git={x['path']:x['sha'] for x in tree['tree'] if x['type']=='blob'}
 for p,b in source.items():require(hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==git[p],'EXACT_GIT_SOURCE')
 require(all(package[p]==source[p] for p in expected),'PACKAGED_SOURCES_MATCH_GIT');profile=json.loads(package['releases/storage-g0-input-preparation-profile-20261106.json']);deps=profile['unchangedDependencySha256'];require(len(deps)==3 and deps==delivery['unchangedDependencies'] and all(sha(source[p])==h for p,h in deps.items()),'THREE_UNCHANGED_DEPENDENCIES')
 require(b'Ran 14 tests' in files['tests.log'] and files['tests.log'].rstrip().endswith(b'OK') and b'skipped' not in files['tests.log'],'FOURTEEN_TESTS_WITHOUT_SKIP')
 return {'schema':'ouf.storage-g0-input-tools-readback.v1','status':'PASS_OFFLINE_NOT_VPS_PREPARATION','deployCommit':tree['sha'],'archiveSha256':expected_sha,'archiveBytes':expected_bytes,'members':6,'checksums':5,'exactGitSources':len(source),'packageMembers':len(package),'packageSha256':delivery['packageSha256'],'manifestSha256':delivery['manifestSha256'],'tests':14,'providerRequests':0,'acceptanceCreditAdded':0}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('archive',type=Path);p.add_argument('sha256');p.add_argument('bytes',type=int);p.add_argument('tree',type=Path);a=p.parse_args();print(json.dumps(verify(a.archive,a.sha256,a.bytes,json.loads(a.tree.read_text())),indent=2))
