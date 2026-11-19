#!/usr/bin/env python3
"""Independent byte-level review of the exported-backup restore evidence."""
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import zipfile

spec=importlib.util.spec_from_file_location('original_reader',Path(__file__).with_name('readback-storage-physical-cut33.py'))
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
require,sha=old.require,old.sha
ORIGINAL_SHA='33b5a7124d3990dce5c0049ff0a33653fec2d6fb29f07edb767a9680b8a441e3'
PRODUCER='7444df039a8b4990d1518a343f4f57a698db0b74'

def verify(archive,source,producer_source,expected_sha,commit):
    raw=archive.read_bytes();require(len(raw)<=64*1024*1024 and sha(raw)==expected_sha,'EXACT_NEW_ARCHIVE')
    with zipfile.ZipFile(archive) as z:
        entries=z.infolist();names=[x.filename for x in entries]
        require(len(names)==len(set(names)) and len(names)<=3000 and sum(x.file_size for x in entries)<=96*1024*1024,'BOUNDED_NEW_ZIP')
        require(all(old.safe(n.rstrip('/')) for n in names),'SAFE_NEW_ZIP')
        payload={x.filename:z.read(x) for x in entries if not x.is_dir()}
    checks={}
    for line in payload['SHA256SUMS'].decode().splitlines():
        digest,name=line.split('  ',1);require(name not in checks and old.safe(name),'UNIQUE_CHECKSUM');checks[name]=digest
    require(set(checks)==set(payload)-{'SHA256SUMS'} and all(sha(payload[n])==h for n,h in checks.items()),'ALL_NEW_BYTES')
    require(payload['build-evidence/repository-commit.txt'].decode().strip()==commit,'EXACT_RESTORE_COMMIT')
    sources={}
    for line in payload['build-evidence/repository-source-sha256.txt'].decode().splitlines():
        digest,name=line.split('  ',1)
        require(old.safe(name) and name not in sources and sha((source/name).read_bytes())==digest,'EXACT_SOURCE:'+name)
        sources[name]=digest
    require(len(sources)==34,'EXACT_34_SOURCE_BINDINGS')
    original=payload['build-evidence/original.zip']
    require(len(original)==6018250 and sha(original)==ORIGINAL_SHA,'UNCHANGED_ORIGINAL_EXPORT')
    with tempfile.TemporaryDirectory() as tmp:
        original_path=Path(tmp)/'original.zip';original_path.write_bytes(original)
        previous=old.verify(original_path,producer_source,ORIGINAL_SHA,PRODUCER)
        with zipfile.ZipFile(original_path) as z:
            original_s3=[json.loads(z.read(n)) for n in z.namelist() if n.endswith('-verify-frozen.json')][0]
            indexes={n:json.loads(z.read('lab/evidence/'+n+'-inventory.json')) for n in ('basebackup','wal-archive','cold-backup')}
            ledger=json.loads(z.read('lab/evidence/source-ledger.json'))
    def doc(name):return json.loads(payload['lab/evidence/'+name+'.json'])
    require(doc('original-readback')==previous,'ORIGINAL_READBACK_REPRODUCED')
    cut=previous['cut'];receipt=doc('receipt');gate=doc('restore-release')
    require(doc('common-cut')==cut and doc('expected-ledger')==doc('restored-ledger')==ledger,'EXACT_EXPORTED_LEDGER')
    require(receipt['status']=='EXPORTED_RESTORE33_PASS' and receipt['allStartedProcessesStopped']
            and receipt['freshHostedRestoreQualified'] and receipt['originalInputsUnchanged'],'NATIVE_EXPORTED_RESTORE_PASS')
    require(receipt['producerCommit']==PRODUCER and receipt['originalRun']==41914041465
            and receipt['originalArtifact']==13362874826 and receipt['originalZipSha256']==ORIGINAL_SHA
            and receipt['restoreCommit']==commit and receipt['restoreRun']!='41914041465'
            and receipt['originalRunDistinctFromRestoreRun'],'DISTINCT_BOUND_HOSTED_RESTORE')
    meta=json.loads(payload['build-evidence/original-artifact.json'])
    job=json.loads(payload['build-evidence/original-native-job.json'])
    require(meta['id']==13362874826 and meta['digest']=='sha256:'+ORIGINAL_SHA
            and meta['workflow_run']['head_sha']==PRODUCER and meta['workflow_run']['id']==41914041465
            and job['id']==126868857170 and job['status']=='completed' and job['conclusion']=='success','ORIGINAL_SUCCESSFUL_PRODUCER')
    require(not receipt['producerWorkingDirectoriesSupplied'] and receipt['fixtureSourceClustersCreated']==receipt['fixtureObjectsSeeded']==0,'EXPORT_ONLY_STATE')
    extraction=doc('extraction')
    require(extraction['status']=='ALL_EXPORTED_BYTES_VERIFIED' and extraction['stateFilesGenerated']==0
            and not extraction['producerWorkingDirectoriesSupplied'],'NO_REGENERATED_STATE')
    for name,index in indexes.items():require(doc(name+'-inventory')==index,'EXACT_EXTRACTED_INVENTORY:'+name)
    require(b'backup successfully verified' in payload['lab/evidence/exported-verifybackup.stdout'],'PG_VERIFYBACKUP_NATIVE_PASS')
    require(gate['status']=='DB_VERIFIED_BEFORE_S3_START' and gate['restoredS3ProcessesStarted']==0
            and gate['sourceSystemIdentifier']==gate['restoredSystemIdentifier']==cut['sourceSystemIdentifier']
            ==receipt['sourceSystemIdentifier']==receipt['restoredSystemIdentifier'],'SAME_PHYSICAL_IDENTITY_BEFORE_S3')
    require(gate['canary']=='cut' and gate['inRecovery']=='f' and gate['ledgerSha256']==cut['ledgerSha256']
            and gate['restoredWriterReserve']==gate['restoredStaleFinish']=='FENCED','PROMOTED_TARGET_AND_PERSISTENT_FENCE')
    ready=doc('restored-sql-readiness');attempts=ready['attempts']
    require(ready['status']=='ACCEPTING_SQL' and ready['readOnlyProbes'] and ready['maxAttempts']==60 and ready['budgetSeconds']==20
            and 1<=len(attempts)<=60 and attempts[-1]['returnCode']==0
            and [x['attempt'] for x in attempts]==list(range(1,len(attempts)+1))
            and all(x['returnCode'] in (1,2) for x in attempts[:-1]),'BOUNDED_READINESS')
    require(b'accepting connections' in payload['lab/evidence/restored-ready-%03d.stdout'%len(attempts)],'NATIVE_SQL_READY')
    events=[json.loads(line) for line in payload['lab/evidence/restored-wal-events.jsonl'].splitlines()]
    segment=cut['targetWalSegment']
    require(any(e.get('name')==segment and e.get('status')=='COPIED' and e.get('sha256')==indexes['wal-archive'][segment]['sha256'] for e in events),'NATIVE_EXPORTED_WAL_REPLAY')
    s3=[json.loads(value) for name,value in payload.items() if name.endswith('-verify-frozen.json')]
    require(s3==[original_s3] and receipt['s3DeniedMutations']==3 and receipt['s3ObjectsReconciled']==2
            and receipt['s3ObjectBytesReadPerPass']==77,'EXACT_NATIVE_S3_READBACK_AND_DENIALS')
    stops=[json.loads(value) for name,value in payload.items() if name.endswith('-stopped.json')]
    require(len(stops)==4 and all(not x['Running'] and x['ExitCode']==0 and not x['OOMKilled'] for x in stops),'FOUR_CLEAN_STORAGE_STOPS')
    require(b'server stopped' in payload['lab/evidence/restored/stop.stdout'],'CLEAN_POSTGRES_STOP')
    tests=payload['build-evidence/offline-tests.log'].decode()
    require(sum(map(int,re.findall(r'Ran (\d+) tests? in ',tests)))==44 and not re.search(r'^FAILED|^OK \(skipped=',tests,re.M),'COMPLETE_44_TEST_SUITE')
    require(receipt['targetOperations']==receipt['mutatingRetries']==receipt['recoveryPutRequests']==0,'NO_TARGET_OR_MUTATING_RETRY')
    return {'status':'EXPORTED_RESTORE33_READBACK_PASS','restoreCommit':commit,'restoreRun':receipt['restoreRun'],
            'archiveSha256':sha(raw),'archiveBytes':len(raw),'members':len(payload),'checksumsVerified':len(checks),
            'sourceBindingsVerified':len(sources),'testsPassed':44,'originalZipSha256':ORIGINAL_SHA,
            'originalChecksumsVerified':previous['checksumsVerified'],'originalSourceBindingsVerified':previous['sourceBindingsVerified'],
            'backupFilesVerified':previous['backupPayloadFilesVerified'],'backupBytesVerified':previous['backupPayloadBytesVerified'],
            'nativeReceipt':receipt,'restoreRelease':gate,'cleanStorageStopsVerified':4,'s3Objects':2,'s3Bytes':77,'targetOperations':0}

if __name__=='__main__':
    result=verify(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]),sys.argv[4],sys.argv[5])
    Path(sys.argv[6]).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print('OUF_EXPORTED_RESTORE_READBACK_JSON='+json.dumps(result,sort_keys=True))
