#!/usr/bin/env python3
"""Read public OCI33 client evidence against independently obtained exact Git trees."""
import argparse, hashlib, io, json, tarfile, zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

IMAGE='sha256:3b972a3ca20f98b73554f0772a2df4f1a5ef4441298299a443f0e605f10ec9b6'
LOCK='c2b30130b078a86ca440351980c3e745d4132e256591ec05fe98a9bdfc9058f8'
APPS={
 'GioNob/ouf-source-onboarding':('onboarding-source','d5155899b09dda298494b68cefa7e1f281167652',[
 'src/main/java/it/comune/trieste/ouf/onboarding/application/ManagedFileStagingStore.java',
 'src/main/java/it/comune/trieste/ouf/onboarding/application/MinioManagedFileStagingStore.java',
 'src/main/java/it/comune/trieste/ouf/onboarding/domain/DomainFailure.java','pom.xml']),
 'GioNob/ouf-udp-object-resolution':('udp-source','0d40da05408a14db31d4d41af2372d6a71480291',[
 'src/main/java/it/comune/trieste/ouf/udp/LakeObjectStoragePort.java',
 'src/main/java/it/comune/trieste/ouf/udp/S3LakeObjectStorageAdapter.java','pom.xml'])}
CASES={'onboardingOriginalAdapterRoundTripAndLimits','reservedReferenceIsValidatedBeforeAnyPut',
 'onboardingTenMiBMultipart','udpOriginalAdapterMetadataReadAndExactDelete','udpInventoryPaginatesBeyondThousand',
 'crossBucketAndUnknownCredentialDenied','versionHistoryAndDeleteMarker','tlsRejectsAnUntrustedCertificate',
 'prefixPolicyAndDeleteDenials','postFormCannotBypassPrefixPolicy','unicodeAndReservedKeyCharactersPreserveBytesAndMetadata',
 'incompleteMultipartIsInventoriableWithoutPublishingAnObject'}
def require(value,code):
 if not value:raise ValueError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def tree_blobs(tree,commit):
 require(tree.get('truncated') is False and tree['sha']==commit,'EXACT_COMPLETE_TREE')
 return {p['path']:p['sha'] for p in tree['tree'] if p['type']=='blob'}
def tar_members(raw):
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
  entries=archive.getmembers();names=[p.name for p in entries]
  require(len(names)==len(set(names)) and all(p.isfile() and p.size<=4*1024*1024 for p in entries) and sum(p.size for p in entries)<=32*1024*1024,'BOUNDED_UNIQUE_REGULAR_SOURCES')
  return {p.name:archive.extractfile(p).read() for p in entries}
def verify(path,tree_path,apps_path,expected_sha,commit):
 raw=path.read_bytes();require(len(raw)<=64*1024*1024 and sha(raw)==expected_sha,'ARCHIVE_DIGEST_SIZE')
 blobs=tree_blobs(json.loads(tree_path.read_text()),commit)
 with zipfile.ZipFile(io.BytesIO(raw)) as archive:
  infos=archive.infolist();names=[p.filename for p in infos]
  require(len(names)==len(set(names)) and all('/' not in n and n not in ['.','..'] for n in names),'FLAT_UNIQUE_MEMBERS')
  require(sum(p.file_size for p in infos)<=64*1024*1024 and all(p.file_size<=16*1024*1024 for p in infos),'BOUNDED_MEMBERS')
  members={n:archive.read(n) for n in names}
 sums={}
 for line in members['SHA256SUMS'].decode().splitlines():
  h,n=line.split('  ',1);require(n not in sums,'DUPLICATE_CHECKSUM');sums[n]=h
 require(set(sums)==set(members)-{'SHA256SUMS'} and all(sha(members[n])==h for n,h in sums.items()),'COMPLETE_CHECKSUM_CLOSURE')
 require(members['source-commit.txt'].decode().strip()==commit,'PRODUCER_COMMIT')
 sources=json.loads(members['source-sha256.json']);source_bytes=tar_members(members['source-files.tar.gz'])
 expected_sources={p for p in blobs if p.startswith(('tools/storage_security/','tests/fixtures/storage-clients33/')) or p.startswith('scripts/') and ('seaweedfs' in p or 'storage' in p) or p in ['.github/workflows/storage-clients33.yml','releases/storage-g0-evidence-request-20261105.json','releases/seaweedfs-452-generation33-candidate-lock-20261104.json']}
 require(set(source_bytes)==set(sources)==expected_sources,'EXACT_COMPLETE_SOURCE_SET')
 for n,b in source_bytes.items():require(sha(b)==sources[n] and blob(b)==blobs.get(n),'EXACT_DEPLOY_SOURCE:'+n)
 require(sha(source_bytes['releases/seaweedfs-452-generation33-candidate-lock-20261104.json'])==LOCK,'EXACT_CANDIDATE_LOCK')
 app_trees=json.loads(apps_path.read_text());app_sources=json.loads(members['application-sources.json']);app_bytes=tar_members(members['application-sources.tar.gz'])
 require(len(app_sources)==7 and len(app_bytes)==7,'SEVEN_APPLICATION_SOURCES')
 expected=set()
 for repo,(prefix,app_commit,paths) in APPS.items():
  app_blobs=tree_blobs(app_trees[repo],app_commit)
  for p in paths:
   name=prefix+'/'+p;expected.add(name);b=app_bytes[name]
   rows=[r for r in app_sources if r['repository']==repo and r['path']==p]
   require(len(rows)==1 and rows[0]['commit']==app_commit and rows[0]['sha256']==sha(b) and rows[0]['gitBlobSha']==blob(b)==app_blobs.get(p),'EXACT_APPLICATION_SOURCE:'+name)
  require(members[prefix+'-pom.xml']==app_bytes[prefix+'/pom.xml'],'POM_COPY_EQUAL')
 require(set(app_bytes)==expected,'EXACT_APPLICATION_MEMBER_SET')
 q=json.loads(members['qualification.json'])
 require(q['status']=='PASS_SYNTHETIC_APPLICATION_ADAPTERS_NOT_TARGET_ACCEPTANCE' and q['producerSource']==commit and q['destinationImage']==IMAGE and q['candidateLockSha256']==LOCK,'EXACT_QUALIFICATION')
 require(q['passed']==12 and q['failed']==q['skipped']==0 and len(q['tests'])==12 and set(q['tests'])==CASES,'TWELVE_EXACT_CASES')
 require(q['targetOperations']==q['gatesClosed']==q['acceptanceTestsPassed']==0 and q['runtimeAuthorityIssued'] is False and q['sourceAdaptersModified'] is False and q['applicationBeansOrEndpointsInstalled'] is False and q['fixtureDependencyClosureDistinctFromFullServices'] is True,'NO_TARGET_OR_FULL_SERVICE_CREDIT')
 xml=ET.fromstring(members['TEST-it.comune.trieste.ouf.storage.StorageClients33Test.xml'])
 require(int(xml.attrib['tests'])==12 and all(int(xml.attrib[k])==0 for k in ['failures','errors','skipped']),'XML_TOTALS')
 cases=xml.findall('testcase');require(len(cases)==12 and {x.attrib['name'] for x in cases}==CASES and all(not any(x.find(t) is not None for t in ['failure','error','skipped']) for x in cases),'XML_CASES')
 scan=json.loads(members['trivy-clients.json']);require(scan.get('SchemaVersion')==2 and scan.get('Results'),'RAW_SCAN_REQUIRED')
 findings=[v for r in scan['Results'] for v in r.get('Vulnerabilities',[]) or []]
 require(not any(v.get('Severity','UNKNOWN') in ['CRITICAL','HIGH','UNKNOWN'] for v in findings),'SECURITY_GATE_HELD')
 isolation=json.loads(members['isolation.json'])
 require(isolation['imageId']==IMAGE and [p['ifname'] for p in isolation['interfaces']]==['lo'] and isolation['routes']==[] and isolation['readOnlyRoot'] is True and isolation['capDrop']==['ALL'] and not isolation['publishedPorts'],'ISOLATION')
 state=json.loads(members['exit.json']);require(state['Running'] is False and state['OOMKilled'] is False and state['ExitCode']==0,'CLEAN_STOP')
 return {'schema':'ouf.storage-clients33-archive-readback.v1','status':'PASS_NOT_SECOND_NATIVE_EXECUTION','sourceCommit':commit,'archiveBytes':len(raw),'archiveSha256':sha(raw),'members':len(members),'checksums':len(sums),'exactDeployGitSources':len(sources),'exactApplicationGitSources':7,'nativeCasesPassed':12,'scanFindings':len(findings),'cleanStop':True,'targetOperations':0,'acceptanceCreditAdded':0}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('archive',type=Path);p.add_argument('tree',type=Path);p.add_argument('application_trees',type=Path);p.add_argument('sha256');p.add_argument('commit');a=p.parse_args();print(json.dumps(verify(a.archive,a.tree,a.application_trees,a.sha256,a.commit),indent=2))
