#!/usr/bin/env python3
"""Bounded archive verification against independently retrieved exact Git trees.

No archive extraction or execution. This is offline readback, not native rerun.
Tree JSON maps 'deploy' and application repository names to recursive Git trees.
"""
import argparse,hashlib,io,json,tarfile,zipfile,sys
from pathlib import Path
def require(ok,why):
 if not ok:raise ValueError(why)
def sha(b):return hashlib.sha256(b).hexdigest()
def readback(path,expected_sha,expected_bytes,trees,kind):
 raw=path.read_bytes();require(len(raw)==expected_bytes and sha(raw)==expected_sha,'EXACT_ARCHIVE')
 z=zipfile.ZipFile(io.BytesIO(raw));names=z.namelist();require(len(names)==len(set(names)) and all('/' not in n and n not in ('','.','..') for n in names),'FLAT_UNIQUE_ARCHIVE')
 require(sum(x.file_size for x in z.infolist())<=32<<20 and all(x.file_size<=8<<20 for x in z.infolist()),'BOUNDED_ARCHIVE');files={n:z.read(n) for n in names};checks={}
 for line in files['SHA256SUMS'].decode().splitlines():
  h,n=line.split('  ',1);require(n not in checks,'UNIQUE_CHECKSUM');checks[n]=h
 require(set(checks)==set(files)-{'SHA256SUMS'} and all(sha(files[n])==h for n,h in checks.items()),'EXACT_CHECKSUM_SET')
 manifest=json.loads(files['source-sha256.json']);sources={}
 with tarfile.open(fileobj=io.BytesIO(files['sources.tar.gz']),mode='r:gz') as t:
  total=0
  for m in t:
   require(m.isfile() and not m.name.startswith('/') and '..' not in Path(m.name).parts and m.name not in sources and m.size<=2<<20,'BOUNDED_REGULAR_SOURCE');total+=m.size;require(total<=16<<20,'BOUNDED_SOURCE_TOTAL');sources[m.name]=t.extractfile(m).read()
 require(set(manifest)==set(sources) and all(sha(b)==manifest[p] for p,b in sources.items()),'EXACT_SOURCE_MANIFEST')
 commits=json.loads(files['source-commits.json']) if kind=='database' else {'deploy':files['source-commit.txt'].decode().strip()}
 expected=set();git={}
 for repo,tree in trees.items():
  require(not tree.get('truncated') and tree['sha']==commits[repo],'EXACT_INDEPENDENT_TREE')
  git[repo]={r['path']:r['sha'] for r in tree['tree'] if r['type']=='blob'}
  if repo!='deploy':expected.update(repo+'/'+p for p in git[repo] if '/db/migration/' in p and p.endswith('.sql'))
 expected.update(p for p in git['deploy'] if p.startswith('tools/storage_inventory/') and (p.endswith('.go') or Path(p).name in ('go.mod','go.sum')))
 expected.update(['scripts/run-storage-g0-qualification.py','.github/workflows/storage-g0-qualification.yml'] if kind=='bodies' else ['tools/storage_planning/g0_database.py','tools/storage_planning/g0_reconciliation.py','tools/storage_planning/inventory_manifest.py','scripts/run-storage-g0-qualification.py','scripts/run-storage-g0-db-qualification.py','.github/workflows/storage-g0-db-qualification.yml','tests/test_storage_g0_database.py','tests/fixtures/storage-g0-db/seed_test.go','tests/fixtures/storage-g0-db/seed.sql'])
 require(set(sources)==expected,'INDEPENDENT_SOURCE_SET')
 for p,b in sources.items():
  parts=p.split('/',1);repo=parts[0] if parts[0] in commits else 'deploy';rel=parts[1] if repo!='deploy' else p
  require(hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==git[repo][rel],'EXACT_GIT_SOURCE_BLOB')
 scan=json.loads(files['trivy.json']);require({'inventory','inventory.test'}<={Path(x['Target']).name for x in scan['Results'] if x.get('Type')=='gobinary'},'TWO_EXECUTABLE_SCANS')
 require(not any(x.get('Vulnerabilities') for x in scan['Results']),'ZERO_SCAN_FINDINGS')
 if kind=='bodies':
  native=json.loads(files['native-minio.json']);r=native['collection'];require(native['status']=='PASS_SYNTHETIC_NOT_TARGET_ACCEPTANCE' and native['objects']==120 and native['bytes']==203743 and native['missingAdvertisedHash']==10 and r['complete'] and r['verifiedBodies']==120 and r['verifiedBytes']==203743 and r['requestsReserved']<=3000 and r['wireBytesRead']<=128<<20 and r['targetWrites']==0 and not r['pointInTimeSnapshotProven'] and not r['runtimeAuthorityIssued'],'NATIVE_BODY_RESULT')
  require(all(native[x] is True for x in ['replayDenied','realProcessCrashScopeRemainsConsumed','hashMismatchHeld','versionedProfileHeldBeforeBodies']),'NATIVE_FAILURE_CASES')
  records=[json.loads(l) for l in files['unit-tests.jsonl'].decode().splitlines() if not l.startswith('go: downloading ')]
  require(not any(r.get('Action') in ('fail','skip') for r in records),'UNIT_OUTCOMES');passes=[r['Test'] for r in records if r.get('Action')=='pass' and 'Test' in r];require(len(passes)==12,'UNIT_COUNT_INCLUDES_SUBTESTS')
  exit=json.loads(files['exit.json']);require(exit['ExitCode']==0 and not exit['OOMKilled'] and not exit['Running'],'CLEAN_BODY_SERVER_STOP')
  detail={'objects':120,'bytes':203743,'unitPassesIncludingSubtests':12,'requestsReserved':r['requestsReserved']}
 else:
  native=json.loads(files['native-db.json']);require(native['status']=='PASS_SYNTHETIC_NOT_TARGET_ACCEPTANCE' and native['conditionalBodies']==2 and native['conditionalBytes']==6 and native['currentProfiles']==3 and native['retainedProfileAlsoQualified'] and native['sameOperationReplayDenied'] and native['incompatibleSchemaDenied'] and native['rawHashDistinctFromCanonicalOutputHash'] and len(native['negativeCases'])==6 and all(native['negativeCases'].values()) and not native['g0Complete'] and not native['runtimeAuthorityIssued'],'NATIVE_DATABASE_RESULT')
  isolation=json.loads(files['database-isolation.json']);require(isolation['migrationsApplied']=={'onboarding':41,'udp':36,'ingestion':18} and isolation['roleDmlDenied'] and isolation['rowSecurityHeldWithoutSilentFiltering'] and isolation['revokedSelectHeld'] and not isolation['routes'] and not isolation['publishedPorts'],'NATIVE_DATABASE_ISOLATION')
  r=json.loads(files['reconciliation.json']);require(r['findingsCount']==0 and r['classifiedBodies']==2 and not r['g0Complete'] and not r['pointInTimeCommonCutProven'] and not r['writerCensus']['intakeComplete'],'OBSERVATION_NOT_ACCEPTANCE')
  root=Path(__file__).resolve().parents[1]
  for p in ['tools/storage_planning/g0_database.py','tools/storage_planning/g0_reconciliation.py','tools/storage_planning/inventory_manifest.py']:require((root/p).read_bytes()==sources[p],'EXACT_LOCAL_OFFLINE_READER_DEPENDENCIES')
  sys.path.insert(0,str(root))
  from tools.storage_planning.g0_database import parse_export
  from tools.storage_planning.g0_reconciliation import reconcile
  exports={p:parse_export(files[p+'-synthetic.jsonl'],p) for p in ['onboarding','udp','ingestion']}
  require(len(parse_export(files['retained-synthetic.jsonl'],'onboarding-retained')['sections'])==7,'RETAINED_EXPORT_READBACK')
  regenerated=reconcile(json.loads(files['synthetic-body-collection.json']),exports,{'onboarding':'ouf-managed-files','udp':'ouf-udp'},{'schema':'ouf.storage-g0-writer-census.v1','installationRef':'synthetic-db-integration','paths':[]})
  require(regenerated==r,'INDEPENDENT_OFFLINE_JOIN_READBACK')
  require(b'Ran 12 tests' in files['unit.log'] and files['unit.log'].rstrip().endswith(b'OK'),'PYTHON_UNIT_RESULTS')
  require(all(x=={'exitCode':0,'oomKilled':False,'running':False} for x in json.loads(files['exits.json']).values()),'CLEAN_DB_FIXTURE_STOPS')
  detail={'objects':2,'bytes':6,'unitTests':12,'nativeNegativeCases':6,'migrations':95}
 return {'schema':'ouf.storage-g0-readback.v1','status':'PASS_OFFLINE_READBACK_NOT_NATIVE_RERUN','kind':kind,'archiveSha256':expected_sha,'archiveBytes':expected_bytes,'members':len(files),'checksums':len(checks),'exactGitSources':len(sources),'commits':commits,'detail':detail,'targetOperations':0,'acceptanceCreditAdded':0}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('archive',type=Path);p.add_argument('sha256');p.add_argument('bytes',type=int);p.add_argument('trees',type=Path);p.add_argument('kind',choices=['bodies','database']);a=p.parse_args();print(json.dumps(readback(a.archive,a.sha256,a.bytes,json.loads(a.trees.read_text()),a.kind),indent=2))
