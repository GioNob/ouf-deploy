#!/usr/bin/env python3
"""Restore the immutable physical-cut export on a fresh hosted execution.

No fixture creation, basebackup generation, bucket creation or object seeding.
Only the three original exported payloads supply database and storage state.
"""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]
def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/filename)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
joint=module('export_joint33','run-storage-physical-cut33-lab.py')
reader=module('export_original33','readback-storage-physical-cut33.py')
common,pitr=joint.common,joint.pitr
require,write=joint.require,joint.write
PRODUCER='7444df039a8b4990d1518a343f4f57a698db0b74'
ORIGINAL_RUN=41914041465
ORIGINAL_ARTIFACT=13362874826
ORIGINAL_BYTES=6018250
ORIGINAL_SHA='33b5a7124d3990dce5c0049ff0a33653fec2d6fb29f07edb767a9680b8a441e3'
COMPONENTS=('basebackup','wal-archive','cold-backup')
# The original tar format stores regular files only. Reconstruct the pinned
# PostgreSQL 17 empty-directory layout, never generate replacement data files.
PG_DIRECTORIES=('base','global','pg_commit_ts','pg_dynshmem','pg_logical',
    'pg_logical/mappings','pg_logical/snapshots','pg_multixact/members',
    'pg_multixact/offsets','pg_notify','pg_replslot','pg_serial','pg_snapshots',
    'pg_stat','pg_stat_tmp','pg_subtrans','pg_tblspc','pg_twophase',
    'pg_wal/archive_status','pg_wal/summaries','pg_xact')

def validate_export(raw,expected):
    actual=reader.tar_inventory(raw)
    require(actual==expected,'EXACT_EXPORTED_COMPONENT')
    for name in actual:
        require(re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*',name)
                and all(p not in ('.','..') for p in PurePosixPath(name).parts),'SAFE_EXPORT_PATH')
        require(not any(str(p) in actual for p in PurePosixPath(name).parents if str(p)!='.'),'NO_FILE_DIRECTORY_COLLISION')
    return actual

def private_directories(root,relative):
    current=root
    for part in PurePosixPath(relative).parts:
        current=current/part
        current.mkdir(mode=0o700,exist_ok=True)

def extract_export(raw,expected,destination):
    validate_export(raw,expected) # Nothing is written before complete validation.
    require(not destination.exists() and not destination.is_symlink(),'FRESH_EXTRACTION_ROOT')
    destination.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
        for member in archive:
            relative=PurePosixPath(member.name)
            private_directories(destination,str(relative.parent))
            target=destination/relative
            with target.open('xb') as out:out.write(archive.extractfile(member).read(member.size+1))
            target.chmod(0o600)
    require(tree_inventory(destination)==expected,'EXTRACTED_COMPONENT_READBACK')

def tree_inventory(root):
    result={}
    for file in sorted(root.rglob('*')):
        require(not file.is_symlink(),'EXTRACTED_SYMLINK_DENIED')
        if file.is_dir():continue
        require(file.is_file(),'EXTRACTED_REGULAR_FILE')
        result[file.relative_to(root).as_posix()]={'bytes':file.stat().st_size,'sha256':pitr.native.digest(file)}
    return result

def execute(original,producer_source,image,pg_bin,work,cohort_receipt):
    require(not work.exists() and not work.is_symlink(),'FRESH_WORK_REQUIRED')
    proof=work/'evidence';proof.mkdir(parents=True,mode=0o700)
    failures=[];pg=None;storage=None
    report={**joint.LIMITS,'status':'EXPORTED_RESTORE33_BLOCKED','producerCommit':PRODUCER,
            'originalRun':ORIGINAL_RUN,'originalArtifact':ORIGINAL_ARTIFACT,
            'originalZipSha256':ORIGINAL_SHA,'mutatingRetries':0,'recoveryPutRequests':0}
    try:
        require(original.stat().st_size==ORIGINAL_BYTES,'ORIGINAL_ARCHIVE_SIZE')
        original_result=reader.verify(original,producer_source,ORIGINAL_SHA,PRODUCER)
        write(proof/'original-readback.json',original_result)
        with zipfile.ZipFile(original) as archive:
            def doc(name):return json.loads(archive.read('lab/evidence/'+name+'.json'))
            cut=doc('common-cut');ledger=doc('source-ledger')
            inventories={name:doc(name+'-inventory') for name in COMPONENTS}
            payloads={name:archive.read('lab/evidence/'+name+'.tar.gz') for name in COMPONENTS}
            observed=[json.loads(archive.read(name)) for name in archive.namelist() if name.endswith('-verify-frozen.json')]
        require(len(observed)==2 and observed[0]==observed[1],'ORIGINAL_S3_PARITY')
        joint.validate_cut(cut,*(inventories[n] for n in COMPONENTS),ledger)
        # Validate all components before extracting any of them or starting a service.
        for name in COMPONENTS:validate_export(payloads[name],inventories[name])
        write(proof/'common-cut.json',cut);write(proof/'expected-ledger.json',ledger)
        for name in COMPONENTS:
            extract_export(payloads[name],inventories[name],work/name)
            write(proof/(name+'-inventory.json'),tree_inventory(work/name))
        base,wal,cold_backup=(work/n for n in COMPONENTS)
        created=[]
        for relative in PG_DIRECTORIES:
            if not (base/relative).exists():created.append(relative)
            private_directories(base,relative)
        for relative in ('master','volume','filer','s3','config'):private_directories(cold_backup,relative)
        write(proof/'extraction.json',{'status':'ALL_EXPORTED_BYTES_VERIFIED','components':list(COMPONENTS),
              'files':{n:len(inventories[n]) for n in COMPONENTS},'emptyPostgresDirectoriesRecreated':created,
              'stateFilesGenerated':0,'producerWorkingDirectoriesSupplied':False})
        tools={}
        for name in ('postgres','pg_verifybackup','pg_waldump','pg_isready'):
            r=pitr.command(proof,name+'-version',[str(pg_bin/name),'--version'])
            require(r.stdout.decode().strip().endswith(' '+pitr.native.VERSION),'PINNED_POSTGRES_TOOL')
            tools[name]={'version':r.stdout.decode().strip(),'sha256':pitr.native.digest(pg_bin/name)}
        write(proof/'tool-identities.json',tools)
        pitr.command(proof,'exported-verifybackup',[str(pg_bin/'pg_verifybackup'),str(base)],timeout=60)
        bound=common.binding(cohort_receipt);cold=common.labs.configured_harness('cold',bound)
        image_root=work/'image';image_root.mkdir()
        write(proof/'exact-image.json',cold.prepare_image(image,image_root))
        pg=joint.prepare_restore(pg_bin,base,wal,work,proof,'restored')
        require(pitr.start_restore(pg,proof,'restored').returncode==0,'EXPORTED_PG_START_REQUIRED')
        readiness=joint.await_sql_ready(pg,proof)
        calls=common.fence.Calls(pg)
        restored=common.ledger_snapshot(calls,proof,'restored')
        restored_id=common.postgres.system_identifier(pg)
        canary=pitr.sql(pg,'SELECT value FROM ouf_joint_probe.boundary;')
        recovery=pitr.sql(pg,'SELECT pg_is_in_recovery();')
        segment=cut['targetWalSegment']
        joint.validate_restored(ledger,restored,cut['sourceSystemIdentifier'],restored_id,canary,recovery,
            joint.events(proof/'restored-wal-events.jsonl'),segment,inventories['wal-archive'][segment]['sha256'])
        reserve=calls.call('reserve','lab-late',2,common.sha(b'late'),4,user=common.fence.WRITER)
        body=common.BODIES['lab-ambiguous']
        finish=calls.call('finish','lab-ambiguous',1,common.sha(body),len(body),user=common.fence.WRITER)
        require(reserve==finish=='FENCED' and json.loads(calls.raw(common.LEDGER_SQL))==ledger,'PERSISTENT_SQL_FENCE')
        write(proof/'restore-release.json',{'status':'DB_VERIFIED_BEFORE_S3_START','restoredS3ProcessesStarted':0,
              'sourceSystemIdentifier':cut['sourceSystemIdentifier'],'restoredSystemIdentifier':restored_id,
              'canary':canary,'inRecovery':recovery,'restoredWriterReserve':reserve,'restoredStaleFinish':finish,
              'ledgerSha256':common.sha(joint.encoded(restored))})
        restored_storage=work/'restored-storage'
        require(cold.cold_copy(cold_backup,restored_storage)==inventories['cold-backup'],'EXACT_COLD_RESTORE')
        cold.command(['sudo','-n','chown','-R','65532:65532',str(restored_storage)])
        storage=cold.Lab('ouf-export33-'+str(os.getpid()),restored_storage,proof);storage.start()
        reread=common.remote(cold,storage,'verify-frozen',proof)
        common.compare_readback(restored,reread);require(reread==observed[0],'EXPORTED_S3_BODY_METADATA_DENIAL_PARITY')
        storage.stop();pg.stop()
        require(all(tree_inventory(work/n)==inventories[n] for n in COMPONENTS),'EXPORTED_INPUTS_UNCHANGED')
        require(pitr.native.digest(original)==ORIGINAL_SHA,'ORIGINAL_ZIP_UNCHANGED')
        report.update(status='EXPORTED_RESTORE33_PASS',freshHostedRestoreQualified=True,
              producerWorkingDirectoriesSupplied=False,fixtureSourceClustersCreated=0,fixtureObjectsSeeded=0,
              originalRunDistinctFromRestoreRun=str(ORIGINAL_RUN)!=os.environ['GITHUB_RUN_ID'],
              restoreRun=os.environ['GITHUB_RUN_ID'],restoreCommit=os.environ['GITHUB_SHA'],
              sourceSystemIdentifier=cut['sourceSystemIdentifier'],restoredSystemIdentifier=restored_id,
              targetName=cut['targetName'],targetLsn=cut['targetLsn'],targetWalSegment=segment,
              sqlReadinessProbeAttempts=len(readiness),s3ObjectsReconciled=2,s3ObjectBytesReadPerPass=77,
              s3DeniedMutations=len(reread['denied']),allAcknowledgementsPreserved=True,
              cleanContainerStops=4,cleanPostgresStops=1,originalInputsUnchanged=True,
              backupFiles={n:len(inventories[n]) for n in COMPONENTS})
        require(report['originalRunDistinctFromRestoreRun'],'DISTINCT_HOSTED_EXECUTION')
    except Exception as error:failures.append(type(error).__name__+': '+str(error)[:512])
    finally:
        if storage and storage.names:
            try:storage.stop()
            except Exception as error:failures.append('storage cleanup: '+str(error)[:256])
        if pg:
            try:pg.stop()
            except Exception as error:failures.append('postgres cleanup: '+str(error)[:256])
        if failures:report.update(status='EXPORTED_RESTORE33_BLOCKED',failures=failures)
        report['allStartedProcessesStopped']=(storage is None or not storage.names) and (pg is None or not pg.started)
        write(proof/'receipt.json',report)
    if failures:raise RuntimeError('; '.join(failures))
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('original','producer-source','image','pg-bin','work','cohort-receipt'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    require(os.environ.get('GITHUB_ACTIONS')=='true' and os.geteuid()!=0,'UNPRIVILEGED_HOSTED_EXECUTION')
    print(json.dumps(execute(args.original.resolve(),args.producer_source.resolve(),args.image.resolve(),
          args.pg_bin.resolve(),args.work.absolute(),args.cohort_receipt.resolve()),sort_keys=True))
