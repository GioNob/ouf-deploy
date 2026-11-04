#!/usr/bin/env python3
"""Read the original physical joint-cut ZIP without starting a second lab."""
import hashlib
import io
import json
from pathlib import Path,PurePosixPath
import re
import sys
import tarfile
import zipfile

def require(ok,code):
    if not ok:raise ValueError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
def safe(name):
    p=PurePosixPath(name)
    return not p.is_absolute() and '..' not in p.parts and '\\' not in name and str(p)==name

def tar_inventory(raw):
    require(len(raw)<=32*1024*1024,'COMPRESSED_TREE_BUDGET')
    result={};total=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
        for m in archive:
            require(safe(m.name) and m.isfile() and not m.issym() and not m.islnk()
                    and m.name not in result and len(result)<3000 and 0<=m.size<=32*1024*1024,'SAFE_REGULAR_TAR_MEMBER')
            total+=m.size;require(total<=256*1024*1024,'EXPANDED_TREE_BUDGET')
            data=archive.extractfile(m).read(m.size+1);require(len(data)==m.size,'EXACT_TAR_SIZE')
            result[m.name]={'bytes':len(data),'sha256':sha(data)}
    require(result,'NONEMPTY_TREE');return result

def verify(archive,source,expected_sha,producer):
    raw=archive.read_bytes();require(len(raw)<=64*1024*1024 and sha(raw)==expected_sha,'EXACT_ORIGINAL_ZIP')
    with zipfile.ZipFile(archive) as z:
        entries=z.infolist();names=[x.filename for x in entries]
        require(len(names)==len(set(names)) and len(names)<=3000 and sum(x.file_size for x in entries)<=96*1024*1024,'BOUNDED_UNIQUE_ZIP')
        require(all(safe(x.filename.rstrip('/')) for x in entries),'SAFE_ZIP_PATHS')
        payload={x.filename:z.read(x) for x in entries if not x.is_dir()}
    checks={}
    for line in payload['SHA256SUMS'].decode().splitlines():
        digest,name=line.split('  ',1);require(name not in checks and safe(name),'UNIQUE_CHECKSUM_PATH');checks[name]=digest
    require(set(checks)==set(payload)-{'SHA256SUMS'},'COMPLETE_CHECKSUM_SET')
    require(all(sha(payload[n])==d for n,d in checks.items()),'EVERY_MEMBER_DIGEST')
    require(payload['build-evidence/repository-commit.txt'].decode().strip()==producer,'EXACT_PRODUCER_COMMIT')
    sources={}
    for line in payload['build-evidence/repository-source-sha256.txt'].decode().splitlines():
        digest,name=line.split('  ',1);require(safe(name) and name not in sources,'UNIQUE_SOURCE');sources[name]=digest
        require(sha((source/name).read_bytes())==digest,'EXACT_SOURCE:'+name)
    require(len(sources)>=30,'COMPLETE_SOURCE_BINDINGS')
    def doc(name):return json.loads(payload['lab/evidence/'+name+'.json'])
    receipt=doc('receipt');cut=doc('common-cut');ledger=doc('source-ledger');restored=doc('restored-ledger')
    require(receipt['status']=='SYNTHETIC_PHYSICAL_COMMON_CUT33_PASS' and receipt['allStartedProcessesStopped'],'NATIVE_JOINT_CUT_PASS')
    require(cut['schema']==receipt['schema']=='ouf.synthetic-physical-common-cut33.v1'
            and cut['targetName']==receipt['targetName']=='ouf_joint33_frozen_epoch2'
            and cut['targetLsn']==receipt['targetLsn'] and cut['timeline']==1,'EXACT_NAMED_CUT')
    require(sha(payload['lab/evidence/common-cut.json'])==receipt['commonCutSha256'],'CUT_DIGEST')
    require(cut['sourcePostgresStopped'] and cut['sourceStorageStoppedAndWithheld'],'QUIESCED_SOURCE_REQUIRED')
    inventories={}
    for name,index,key in [('basebackup','basebackup-inventory','baseIndexSha256'),
                           ('wal-archive','wal-archive-inventory','walIndexSha256'),
                           ('cold-backup','cold-backup-inventory','coldIndexSha256')]:
        data=payload['lab/evidence/'+name+'.tar.gz']
        require(sha(data)==receipt['backupArchives'][name],'ORIGINAL_BACKUP_ARCHIVE_HASH')
        actual=tar_inventory(data);expected=doc(index)
        require(actual==expected and sha(payload['lab/evidence/'+index+'.json'])==cut[key],'EVERY_PACKAGED_BACKUP_BYTE')
        inventories[name]=actual
    segment=cut['targetWalSegment']
    require(segment==receipt['targetWalSegment'] and re.fullmatch(r'[0-9A-F]{24}',segment)
            and segment in inventories['wal-archive'] and 'pg_wal/'+segment not in inventories['basebackup'],'REQUIRED_POST_BASE_WAL')
    require(inventories['cold-backup']['config/s3.json']['sha256']==cut['readOnlyConfigSha256'],'READ_ONLY_CONFIG_BOUND')
    require(sha(payload['lab/evidence/source-ledger.json'])==cut['ledgerSha256']
            and ledger==restored==doc('source-after-target')['ledger'],'EXACT_CATALOG_ACK_HISTORY')
    require(ledger['control']=={'singleton':True,'epoch':2,'version':2,'phase':'FROZEN'},'FROZEN_CONTROL')
    bodies={'lab-acked':b'acknowledged before common cut\x00\xff','lab-ambiguous':b'effect durable, publication response absent\x00\xff'}
    intents=[{'operation':op,'epoch':1,'body_hash':sha(body),'body_bytes':len(body),
              'state':'ACKED' if op=='lab-acked' else 'RECONCILED'} for op,body in sorted(bodies.items())]
    require(ledger['intents']==intents,'EXACT_RECONCILED_OBJECTS')
    expected_events=[('RESERVED','lab-acked',1,0),('ACKED','lab-acked',1,0),('RESERVED','lab-ambiguous',1,0),
                     ('DRAINING',None,2,1),('RECONCILED','lab-ambiguous',2,1),('FROZEN',None,2,2)]
    rows=ledger['events'];seq=[x['sequence'] for x in rows]
    require(len(rows)==6 and all(type(n) is int and n>0 for n in seq) and all(a<b for a,b in zip(seq,seq[1:])), 'ORDERED_EVENT_HISTORY')
    require(rows==[dict(sequence=n,kind=k,operation=o,epoch=e,version=v) for n,(k,o,e,v) in zip(seq,expected_events)],'EXACT_EVENT_PAYLOADS')
    pre=doc('pre-drain-ledger');require(rows[:len(pre['events'])]==pre['events'],'PRESERVED_ORIGINAL_ACK')
    base=doc('base-ledger')
    require(base['control']=={'singleton':True,'epoch':1,'version':0,'phase':'ACTIVE'} and base['intents'] is None,'INTENTS_ABSENT_FROM_BASEBACKUP')
    gate=doc('restore-release');negative=doc('missing-wal-gate')
    require(gate['status']=='DB_VERIFIED_BEFORE_S3_START' and gate['restoredS3ProcessesStarted']==0
            and gate['sourceSystemIdentifier']==gate['restoredSystemIdentifier']==cut['sourceSystemIdentifier']
            ==receipt['sourceSystemIdentifier']==receipt['restoredSystemIdentifier'],'EXACT_PHYSICAL_IDENTITY_AND_START_GATE')
    require(gate['canary']=='cut' and gate['inRecovery']=='f' and doc('source-after-target')['canary']=='after-cut'
            and gate['ledgerSha256']==cut['ledgerSha256'],'NAMED_TARGET_NOT_END_OF_WAL')
    require(gate['restoredWriterReserve']==gate['restoredStaleFinish']=='FENCED','PERSISTENT_FENCE_AFTER_PROMOTION')
    require(negative['status']=='BLOCKED_BEFORE_S3_RESTORE' and negative['postgresTerminated']
            and negative['restoredS3ProcessesStarted']==0 and negative['sourceProcessesStopped']
            and negative['targetWalSegment']==segment and negative['mutatingRetries']==0,'MISSING_WAL_FAILS_CLOSED')
    require(b'recovery ended before configured recovery target was reached' in payload['lab/evidence/missing-wal/postgres.log'],'NATIVE_MISSING_WAL_FAILURE')
    read_events=[json.loads(l) for l in payload['lab/evidence/restored-wal-events.jsonl'].splitlines()]
    require(any(e.get('name')==segment and e.get('status')=='COPIED' and e.get('sha256')==inventories['wal-archive'][segment]['sha256'] for e in read_events),'NATIVE_ARCHIVE_REPLAY')
    missing=[json.loads(l) for l in payload['lab/evidence/missing-wal-wal-events.jsonl'].splitlines()]
    require(any(e.get('name')==segment and e.get('status')=='MISSING' for e in missing),'NATIVE_MISSING_ARCHIVE_READ')
    s3=[json.loads(v) for n,v in payload.items() if n.endswith('-verify-frozen.json')]
    require(len(s3)==2 and s3[0]==s3[1],'SOURCE_RESTORED_S3_PARITY')
    expected_objects={op:{'sha256':sha(body),'bytes':len(body),'mime':'application/octet-stream'} for op,body in bodies.items()}
    require(all(x['objects']==expected_objects and x['mutatingRetries']==0 for x in s3),'EXACT_S3_OBJECT_READBACK')
    denials=[{'method':m,'key':k,'status':403,'code':'AccessDenied'} for m,k in [('PUT','lab-late'),('PUT','lab-acked'),('DELETE','lab-acked')]]
    require(all(x['denied']==denials for x in s3),'SIX_EXPLICIT_S3_DENIALS')
    stops=[json.loads(v) for n,v in payload.items() if n.endswith('-stopped.json')]
    require(len(stops)==12 and all(not x['Running'] and x['ExitCode']==0 and not x['OOMKilled'] for x in stops),'TWELVE_CLEAN_STORAGE_STOPS')
    for name in ('postgres-source','restored'):
        require(b'server stopped' in payload['lab/evidence/'+name+'/stop.stdout'],'CLEAN_POSTGRES_STOP')
    tests=payload['build-evidence/offline-tests.log'].decode()
    require(sum(map(int,re.findall(r'Ran (\d+) tests? in ',tests)))==32 and not re.search(r'^FAILED|^OK \(skipped=',tests,re.M),'COMPLETE_32_TEST_SUITE')
    require(receipt['targetOperations']==receipt['mutatingRetries']==receipt['recoveryPutRequests']==receipt['excludedPostTargetObjectAcknowledgements']==0,'NO_TARGET_OR_REPLAY_OR_ACK_LOSS')
    return {'status':'ORIGINAL_PHYSICAL_COMMON_CUT_READBACK_PASS','producerCommit':producer,
            'originalZipSha256':sha(raw),'originalZipBytes':len(raw),'members':len(payload),'checksumsVerified':len(checks),
            'sourceBindingsVerified':len(sources),'testsPassed':32,'backupPayloadFilesVerified':{k:len(v) for k,v in inventories.items()},
            'backupPayloadBytesVerified':{k:sum(x['bytes'] for x in v.values()) for k,v in inventories.items()},
            'cut':cut,'nativeReceipt':receipt,'missingWalGate':negative,'restoreRelease':gate,
            'cleanStorageStopsVerified':len(stops),'s3Objects':len(bodies),'s3Bytes':sum(map(len,bodies.values())),
            'secondNativeRestore':False,'targetOperations':0}

if __name__=='__main__':
    result=verify(Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3],sys.argv[4])
    Path(sys.argv[5]).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print('OUF_PHYSICAL_CUT_READBACK_JSON='+json.dumps(result,sort_keys=True))
