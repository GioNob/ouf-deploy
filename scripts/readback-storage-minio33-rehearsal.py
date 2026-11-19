#!/usr/bin/env python3
"""Read a bounded public rehearsal archive against the exact GitHub commit tree.
The tree must be obtained independently from the repository, not from the ZIP.
"""
import argparse, hashlib, io, json, tarfile, zipfile
from pathlib import Path

def require(condition,message):
 if not condition:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def verify(path,tree_path,expected_sha,commit):
 raw=path.read_bytes();require(len(raw)<=64*1024*1024 and sha(raw)==expected_sha,'ARCHIVE_DIGEST_OR_SIZE')
 tree=json.loads(tree_path.read_text());require(not tree.get('truncated') and tree['sha']==commit,'EXACT_COMPLETE_COMMIT_TREE')
 blobs={p['path']:p['sha'] for p in tree['tree'] if p['type']=='blob'}
 with zipfile.ZipFile(io.BytesIO(raw)) as archive:
  infos=archive.infolist();names=[p.filename for p in infos]
  require(len(names)==len(set(names)) and all('/' not in n and n not in ['.','..'] for n in names),'FLAT_UNIQUE_MEMBERS')
  require(sum(p.file_size for p in infos)<=64*1024*1024 and all(p.file_size<=16*1024*1024 for p in infos),'MEMBER_SIZE_BUDGET')
  members={name:archive.read(name) for name in names}
 sums={}
 for line in members['SHA256SUMS'].decode().splitlines():
  digest,name=line.split('  ',1);require(name not in sums,'DUPLICATE_CHECKSUM');sums[name]=digest
 require(set(sums)==set(members)-{'SHA256SUMS'} and all(sha(members[n])==h for n,h in sums.items()),'COMPLETE_CHECKSUM_CLOSURE')
 require(members['source-commit.txt'].decode().strip()==commit,'PRODUCER_COMMIT')
 sources=json.loads(members['source-sha256.json'])
 with tarfile.open(fileobj=io.BytesIO(members['source-files.tar.gz']),mode='r:gz') as archive:
  infos=archive.getmembers();require(len(infos)==len(sources) and {p.name for p in infos}==set(sources),'EXACT_SOURCE_MEMBERS')
  require(all(p.isfile() and p.size<=4*1024*1024 for p in infos) and sum(p.size for p in infos)<=32*1024*1024,'BOUNDED_REGULAR_SOURCES')
  for info in infos:
   body=archive.extractfile(info).read();git_sha=hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()
   require(sha(body)==sources[info.name] and blobs.get(info.name)==git_sha,'EXACT_GIT_SOURCE:'+info.name)
 qualification=json.loads(members['qualification.json']);roundtrip=json.loads(members['roundtrip.json']);post=json.loads(members['post-write-return.json'])
 require(qualification['producerSource']==commit and qualification['status']=='PASS_SYNTHETIC_NOT_ACCEPTANCE','QUALIFICATION_PASS')
 require(qualification['targetOperations']==qualification['gatesClosed']==qualification['realObjectsCopied']==0 and qualification['runtimeAuthorityIssued'] is False,'NO_ACCEPTANCE_OR_AUTHORITY')
 require(qualification['sourceImage']=='sha256:69b2ec208575b69597784255eec6fa6a2985ee9e1a47f4411a51f7f5fdd193a9' and qualification['destinationImage']=='sha256:3b972a3ca20f98b73554f0772a2df4f1a5ef4441298299a443f0e605f10ec9b6','EXACT_PROVIDERS')
 expected=['TestRealFunctionalReadiness','TestMinio33RoundTrip','TestMinio33PostWriteReturn','TestRealProcessCrashResumeNoSecondPut','TestRealAmbiguous503RespectsRetryAfterAndReconciles','TestMinio33TagsAndEncoding','TestRealSourceIfMatchAndVersionedDestinationDenials']
 passed=[]
 for case in expected:
  rows=[json.loads(line) for line in members[case+'.jsonl'].splitlines()]
  require(not any(r.get('Action') in ['fail','skip'] for r in rows) and any(r.get('Action')=='pass' and r.get('Test')==case for r in rows),'NATIVE_CASE:'+case)
  passed.extend(r['Test'] for r in rows if r.get('Action')=='pass' and 'Test' in r)
 require(passed==qualification['passedTests'] and len(passed)==12,'EXACT_NATIVE_CASE_SET')
 require(roundtrip['status']=='PASS_SYNTHETIC_NOT_ACCEPTANCE' and roundtrip['objects']==120 and roundtrip['bytes']==203743 and roundtrip['missingAdvertisedHashes']==10 and roundtrip['independentConditionalBodyReads']==360 and roundtrip['returnInitiallyEmpty'] is True,'ROUNDTRIP_COUNTS')
 require(roundtrip['reverseReport']['Verified']==roundtrip['reverseReport']['CopiedThisAttempt']==120,'REVERSE_REPORT')
 parity=roundtrip['objectsParity'];require(len(parity)==120,'ALL_OBJECT_PARITY')
 for i,row in enumerate(parity):
  size=84743 if i==119 else 1000;key='private/è%2F?+#' if i==0 else 'object-%03d'%i
  require(row['id']=={'Bucket':['lab-copy-a','lab-copy-b'][i//60],'Key':key} and row['bytes']==size and row['sha256ByProvider']==[sha(bytes([i])*size)]*3,'INDEPENDENT_EXPECTED_SYNTHETIC_BODY')
 require(post['status']=='PASS_SYNTHETIC_NOT_ACCEPTANCE' and post['acknowledgedMutations']==['REPLACE_BODY','REPLACE_METADATA','DELETE','ADD'] and post['returnedCurrentObjects']==3 and all(post[k] is True for k in ['returnInitiallyEmpty','deletedObjectAbsent','sourceOriginalsUnchanged']) and post['dbReferencesReconciled'] is False and post['runtimeRollbackAdmitted'] is False,'POST_WRITE_RETURN_SCOPE')
 isolation=json.loads(members['isolation.json']);require([p['ifname'] for p in isolation['interfaces']]==['lo'] and isolation['routes']==[] and len(isolation['containers'])==3,'ISOLATED_NETWORK')
 require(isolation['legacySourceProductionSecurityGate']=='HELD_UNCHANGED' and isolation['publisherAuthenticatedForLegacyMinio'] is False,'LEGACY_GATE_PRESERVED')
 for name in ['trivy-tools.json','trivy-binaries.json']:
  scan=json.loads(members[name]);require(scan['SchemaVersion']==2 and scan['Results'],'RAW_SCAN_REQUIRED')
  require(not any(v.get('Severity','UNKNOWN') in ['CRITICAL','HIGH','UNKNOWN'] for r in scan['Results'] for v in r.get('Vulnerabilities',[]) or []),'TOOL_SCAN_HELD')
 exits=[json.loads(v) for k,v in members.items() if k.endswith('-exit.json')];require(len(exits)==3 and all(not v['Running'] and not v['OOMKilled'] and v['ExitCode']==0 for v in exits),'THREE_CLEAN_STOPS')
 return {'schema':'ouf.minio33-archive-readback.v1','status':'PASS_NOT_SECOND_NATIVE_EXECUTION','sourceCommit':commit,'archiveBytes':len(raw),'archiveSha256':sha(raw),'members':len(members),'checksums':len(sums),'exactGitSources':len(sources),'nativePassesIncludingSubtests':len(passed),'syntheticObjects':120,'bytesPerCopy':203743,'conditionalBodyReads':360,'postWriteMutations':post['acknowledgedMutations'],'threeCleanStops':True,'targetOperations':0}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('archive',type=Path);p.add_argument('tree',type=Path);p.add_argument('sha256');p.add_argument('commit');a=p.parse_args();print(json.dumps(verify(a.archive,a.tree,a.sha256,a.commit),indent=2))
