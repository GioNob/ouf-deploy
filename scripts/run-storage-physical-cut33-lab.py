#!/usr/bin/env python3
"""Named PostgreSQL recovery point bound to a fenced cold SeaweedFS33 cut.

Disposable public fixture only. Reuse existing common-cut and WAL transports;
do not change historical laboratories or claim production admission/RPO/RTO.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
spec=importlib.util.spec_from_file_location('joint_common33',ROOT/'scripts/run-storage-coordinated33-lab.py')
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
import run_storage_postgres_pitr as pitr
require,write=common.require,common.write
TARGET='ouf_joint33_frozen_epoch2'
LIMITS={**common.LIMITS,'targetPitrQualified':False,'zeroProductionAcknowledgedLossQualified':False}
SCHEMA='ouf.synthetic-physical-common-cut33.v1'


def encoded(value):
    return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()


def validate_cut(cut,base,wal,storage,ledger):
    common.validate_ledger(ledger)
    require(cut['schema']==SCHEMA and cut['targetName']==TARGET and cut['timeline']==1,
            'EXACT_JOINT_RECOVERY_TARGET')
    require(re.fullmatch(r'[0-9A-F]+/[0-9A-F]+',cut['targetLsn']) is not None
            and re.fullmatch(r'[0-9A-F]{24}',cut['targetWalSegment']) is not None,
            'EXACT_WAL_TARGET_IDENTITY')
    require(cut['lockSha256']==common.LOCK_SHA and cut['cohortReceiptSha256']==common.COHORT_SHA,
            'EXACT_GENERATION33_COHORT')
    require(cut['sourceSystemIdentifier'].isdecimal() and cut['sourcePostgresStopped']
            and cut['sourceStorageStoppedAndWithheld'],'SOURCES_STOPPED_BEFORE_RESTORE')
    require('pg_wal/'+cut['targetWalSegment'] not in base and cut['targetWalSegment'] in wal,
            'POST_BASE_TARGET_WAL_REQUIRED')
    for key,inventory in [('baseIndexSha256',base),('walIndexSha256',wal),('coldIndexSha256',storage)]:
        require(cut[key]==common.sha(encoded(inventory)),'BOUND_BACKUP_COMPONENT:'+key)
    require(cut['ledgerSha256']==common.sha(encoded(ledger)),'BOUND_FROZEN_LEDGER')
    require(storage['config/s3.json']['sha256']==cut['readOnlyConfigSha256'],'BOUND_READ_ONLY_STORAGE')
    return True


def validate_restored(ledger,restored,source_id,restored_id,canary,in_recovery,wal_reads,segment,digest):
    common.validate_ledger(ledger);common.validate_ledger(restored)
    require(restored==ledger,'EXACT_ACK_FENCE_HISTORY_AFTER_PHYSICAL_RECOVERY')
    require(source_id==restored_id and source_id.isdecimal(),'SAME_PHYSICAL_CLUSTER_ID_REQUIRED')
    require(canary=='cut' and in_recovery=='f','EXACT_NAMED_TARGET_PROMOTED')
    require(any(e.get('name')==segment and e.get('status')=='COPIED'
                and e.get('sha256')==digest for e in wal_reads),'ACTUAL_POST_BASE_WAL_READ_REQUIRED')


def prepare_restore(pg_bin,base,archive,work,proof,label):
    lab=pitr.restore_lab(pg_bin,base,archive,work,proof,label)
    # No SQL readiness before the named target. Promotion permits proving that
    # the persisted writer fence (not standby read-only mode) rejects writes.
    pitr.append_settings(lab.data,"recovery_target_name = '%s'\nrecovery_target_action = 'promote'\nhot_standby = off\n"%TARGET)
    return lab



def await_sql_ready(destination,proof):
    """A running postmaster is not necessarily accepting SQL during recovery."""
    deadline=time.monotonic()+20;observations=[]
    for attempt in range(1,61):
        result=pitr.command(proof,'restored-ready-%03d'%attempt,
            [str(destination.binary('pg_isready')),'--host='+str(destination.socket),
             '--port='+str(pitr.native.PORT),'--username=fixture_admin',
             '--dbname='+pitr.native.ROLE,'--timeout=2'],timeout=3,allow_failure=True)
        observations.append({'attempt':attempt,'returnCode':result.returncode})
        write(proof/'restored-sql-readiness.json',{'status':'ACCEPTING_SQL' if result.returncode==0 else 'WAITING',
              'attempts':observations,'readOnlyProbes':True,'maxAttempts':60,'budgetSeconds':20})
        if result.returncode==0:return observations
        require(result.returncode in (1,2),'PERMANENT_READINESS_PROBE_FAILURE')
        require(time.monotonic()<deadline,'SQL_READINESS_BUDGET_EXHAUSTED')
        if attempt<60:time.sleep(.25)
    raise RuntimeError('SQL_READINESS_BUDGET_EXHAUSTED')

def events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def execute(image,pg_bin,work,receipt):
    bound=common.binding(receipt);cold=common.labs.configured_harness('cold',bound)
    proof=work/'evidence';proof.mkdir(parents=True,mode=0o700)
    source_pg=common.postgres.native.NativeLab(pg_bin,proof/'postgres-source')
    destinations=[];containers=[];failures=[]
    report={**LIMITS,'status':'SYNTHETIC_PHYSICAL_COMMON_CUT33_BLOCKED'}
    try:
        image_root=work/'image';image_root.mkdir()
        write(proof/'exact-image.json',cold.prepare_image(image,image_root))
        original=work/'original'
        for role in ('master','volume','filer','s3','config'):(original/role).mkdir(parents=True)
        write(original/'config/s3.json',common.configuration(cold,True))
        cold.command(['sudo','-n','chown','-R','65532:65532',str(original)])
        source_pg.start(initialize_catalog=False)
        source_pg.sql((ROOT/'tests/fixtures/storage-recovery/writer-fence.sql').read_text())
        source_pg.sql("CREATE SCHEMA ouf_joint_probe; CREATE TABLE ouf_joint_probe.boundary(value text NOT NULL); INSERT INTO ouf_joint_probe.boundary VALUES('base');")
        source_id=common.postgres.system_identifier(source_pg)
        wal=work/'wal-archive';wal.mkdir(mode=0o700)
        pitr.append_settings(source_pg.data,"wal_level = replica\nfull_page_writes = on\narchive_mode = on\narchive_command = '%s'\n"%pitr.archive_command('archive',wal,proof/'archive-events.jsonl'))
        pitr.restart_source(source_pg,proof)
        require(pitr.sql(source_pg,'SHOW wal_segment_size;')=='16MB'
                and pitr.sql(source_pg,'SHOW archive_mode;')=='on','ARCHIVE_CONFIGURATION_REQUIRED')
        tools={}
        for name in ('pg_basebackup','pg_verifybackup','pg_waldump','pg_isready'):
            binary=pg_bin/name;r=pitr.command(proof,name+'-version',[str(binary),'--version'])
            require(r.stdout.decode().strip().endswith(' '+pitr.native.VERSION),'PINNED_PHYSICAL_TOOL')
            tools[name]={'version':r.stdout.decode().strip(),'sha256':pitr.native.digest(binary)}
        write(proof/'backup-tool-identities.json',tools)
        calls=common.fence.Calls(source_pg)
        write(proof/'base-ledger.json',json.loads(calls.raw(common.LEDGER_SQL)))
        base=work/'basebackup'
        pitr.command(proof,'basebackup',[str(pg_bin/'pg_basebackup'),'--pgdata='+str(base),
            '--host='+str(source_pg.socket),'--port='+str(pitr.native.PORT),'--username=fixture_admin',
            '--no-password','--checkpoint=fast','--wal-method=stream','--manifest-checksums=SHA256',
            '--label=ouf-joint33-before-intents'],timeout=90)
        pitr.command(proof,'verifybackup',[str(pg_bin/'pg_verifybackup'),str(base)],timeout=60)
        base_inventory=pitr.inventory(base);write(proof/'basebackup-inventory.json',base_inventory)
        pitr.sql(source_pg,'CHECKPOINT; SELECT pg_switch_wal();')
        prefix='ouf-joint33-'+str(os.getpid())
        source=cold.Lab(prefix+'-source',original,proof);containers.append(source);source.start()
        common.remote(cold,source,'bucket',proof)
        for op,body in common.BODIES.items():
            require(calls.call('reserve',op,1,common.sha(body),len(body),user=common.fence.WRITER)=='RESERVED',
                    'INTENT_BEFORE_OBJECT_REQUIRED')
            common.remote(cold,source,op,proof)
            if op=='lab-acked':
                require(calls.call('finish',op,1,common.sha(body),len(body),user=common.fence.WRITER)=='ACKED','ACK_REQUIRED')
        prefix_ledger=json.loads(calls.raw(common.LEDGER_SQL));write(proof/'pre-drain-ledger.json',prefix_ledger)
        require(calls.call('begin_drain',1,0)=='DRAINING','DRAIN_REQUIRED')
        body=common.BODIES['lab-ambiguous']
        require(calls.call('finish','lab-ambiguous',1,common.sha(body),len(body),user=common.fence.WRITER)=='FENCED','LATE_ACK_FENCED')
        require(calls.call('reserve','lab-late',1,common.sha(b'late'),4,user=common.fence.WRITER)=='FENCED','LATE_CLAIM_FENCED')
        require(calls.call('finish_drain',1)=='RECONCILE_REQUIRED','PENDING_BLOCKS_CUT')
        source.stop()
        cold.command(['sudo','-n','chown','-R',f'{os.getuid()}:{os.getgid()}',str(original)])
        write(original/'config/s3.json',common.configuration(cold,False))
        readonly_sha=pitr.native.digest(original/'config/s3.json')
        cold.command(['sudo','-n','chown','-R','65532:65532',str(original)])
        frozen=cold.Lab(prefix+'-fenced',original,proof);containers.append(frozen);frozen.start()
        observed=common.remote(cold,frozen,'verify-frozen',proof)
        identity=observed['objects']['lab-ambiguous']
        require(calls.call('reconcile','lab-ambiguous',1,identity['sha256'],identity['bytes'])=='RECONCILED','RECONCILE_REQUIRED')
        require(calls.call('finish_drain',1)=='FROZEN','FROZEN_CUT_REQUIRED')
        ledger=common.ledger_snapshot(calls,proof,'source')
        common.validate_preserved_prefix(prefix_ledger,ledger);common.compare_readback(ledger,observed)
        frozen.stop()
        pitr.sql(source_pg,"UPDATE ouf_joint_probe.boundary SET value='cut';")
        target_lsn=pitr.sql(source_pg,"SELECT pg_create_restore_point('%s');"%TARGET)
        target_segment=pitr.sql(source_pg,"SELECT pg_walfile_name('%s'::pg_lsn);"%target_lsn)
        require('pg_wal/'+target_segment not in base_inventory,'POST_BASE_TARGET_REQUIRED')
        # This non-domain canary distinguishes the named target from end-of-WAL.
        # No later object/ACK is created or intentionally discarded.
        pitr.sql(source_pg,"UPDATE ouf_joint_probe.boundary SET value='after-cut';")
        write(proof/'source-after-target.json',{'canary':pitr.sql(source_pg,'SELECT value FROM ouf_joint_probe.boundary;'),
              'ledger':json.loads(calls.raw(common.LEDGER_SQL))})
        require(json.loads(calls.raw(common.LEDGER_SQL))==ledger,'FROZEN_LEDGER_CHANGED')
        pitr.sql(source_pg,'SELECT pg_switch_wal();')
        deadline=time.monotonic()+15
        while not (wal/target_segment).is_file():
            require(time.monotonic()<deadline,'TARGET_ARCHIVE_TIMEOUT');time.sleep(.1)
        require(pitr.read_regular(wal/target_segment)==pitr.read_regular(source_pg.data/'pg_wal'/target_segment),'ARCHIVED_TARGET_BYTES_REQUIRED')
        source_pg.stop()
        cold.command(['sudo','-n','chown','-R',f'{os.getuid()}:{os.getgid()}',str(original)])
        cold_backup=work/'cold-backup';storage_inventory=cold.cold_copy(original,cold_backup)
        original.rename(work/'withheld-original')
        wal_inventory=pitr.inventory(wal)
        write(proof/'wal-archive-inventory.json',wal_inventory);write(proof/'cold-backup-inventory.json',storage_inventory)
        cut={'schema':SCHEMA,'targetName':TARGET,'targetLsn':target_lsn,'targetWalSegment':target_segment,'timeline':1,
             'sourceSystemIdentifier':source_id,'lockSha256':common.LOCK_SHA,'cohortReceiptSha256':common.COHORT_SHA,
             'baseIndexSha256':common.sha(encoded(base_inventory)),'walIndexSha256':common.sha(encoded(wal_inventory)),
             'coldIndexSha256':common.sha(encoded(storage_inventory)),'ledgerSha256':common.sha(encoded(ledger)),
             'readOnlyConfigSha256':readonly_sha,'sourcePostgresStopped':not source_pg.started,
             'sourceStorageStoppedAndWithheld':not source.names and not frozen.names and (work/'withheld-original').is_dir()}
        validate_cut(cut,base_inventory,wal_inventory,storage_inventory,ledger);write(proof/'common-cut.json',cut)
        for directory,name in [(base,'basebackup'),(wal,'wal-archive'),(cold_backup,'cold-backup')]:
            pitr.package(directory,proof/(name+'.tar.gz'))
        # Exercise a native failure before any restored S3 service may start.
        incomplete=work/'incomplete-wal';shutil.copytree(wal,incomplete);(incomplete/target_segment).unlink()
        negative=prepare_restore(pg_bin,base,incomplete,work,proof,'missing-wal');destinations.append(negative)
        failure=pitr.start_restore(negative,proof,'missing-wal');pitr.stop_failed_restore(negative,proof)
        missing_log=(negative.output/'postgres.log').read_text()
        require('recovery ended before configured recovery target was reached' in missing_log,'MISSING_TARGET_MUST_FAIL')
        require(any(e['name']==target_segment and e['status']=='MISSING' for e in events(proof/'missing-wal-wal-events.jsonl')),'MISSING_TARGET_READ_REQUIRED')
        require(len(containers)==2 and all(not c.names for c in containers),'NO_S3_START_AFTER_FAILED_PITR')
        write(proof/'missing-wal-gate.json',{'status':'BLOCKED_BEFORE_S3_RESTORE','targetWalSegment':target_segment,
              'postgresTerminated':not negative.started,'restoredS3ProcessesStarted':0,'sourceProcessesStopped':True,
              'pgCtlStartReturnCode':failure.returncode,'mutatingRetries':0})
        restored_pg=prepare_restore(pg_bin,base,wal,work,proof,'restored');destinations.append(restored_pg)
        require(pitr.start_restore(restored_pg,proof,'restored').returncode==0,'POSITIVE_TARGET_START_REQUIRED')
        readiness=await_sql_ready(restored_pg,proof)
        restored_calls=common.fence.Calls(restored_pg)
        restored_ledger=common.ledger_snapshot(restored_calls,proof,'restored')
        restored_id=common.postgres.system_identifier(restored_pg)
        canary=pitr.sql(restored_pg,'SELECT value FROM ouf_joint_probe.boundary;')
        recovery=pitr.sql(restored_pg,'SELECT pg_is_in_recovery();')
        reads=events(proof/'restored-wal-events.jsonl')
        validate_restored(ledger,restored_ledger,source_id,restored_id,canary,recovery,reads,target_segment,wal_inventory[target_segment]['sha256'])
        require(restored_calls.call('reserve','lab-late',2,common.sha(b'late'),4,user=common.fence.WRITER)=='FENCED','RESTORED_PERSISTENT_FENCE')
        require(restored_calls.call('finish','lab-ambiguous',1,common.sha(body),len(body),user=common.fence.WRITER)=='FENCED','RESTORED_STALE_ACK_FENCE')
        require(json.loads(restored_calls.raw(common.LEDGER_SQL))==ledger,'DENIED_SQL_MUST_PRESERVE_LEDGER')
        write(proof/'restore-release.json',{'status':'DB_VERIFIED_BEFORE_S3_START','sourceSystemIdentifier':source_id,
              'restoredSystemIdentifier':restored_id,'canary':canary,'inRecovery':recovery,
              'ledgerSha256':common.sha(encoded(restored_ledger)),'restoredWriterReserve':'FENCED','restoredStaleFinish':'FENCED',
              'restoredS3ProcessesStarted':0})
        restored_root=work/'restored-storage'
        require(cold.cold_copy(cold_backup,restored_root)==storage_inventory,'EXACT_INDEPENDENT_COLD_RESTORE')
        cold.command(['sudo','-n','chown','-R','65532:65532',str(restored_root)])
        restored=cold.Lab(prefix+'-restored',restored_root,proof);containers.append(restored);restored.start()
        reread=common.remote(cold,restored,'verify-frozen',proof);common.compare_readback(restored_ledger,reread)
        require(reread==observed,'RESTORED_BODY_METADATA_DENIAL_PARITY')
        restored.stop();restored_pg.stop()
        require(pitr.inventory(base)==base_inventory and pitr.inventory(wal)==wal_inventory
                and cold.cold_copy(cold_backup,work/'custody-readback')==storage_inventory,'ORIGINAL_BACKUPS_UNCHANGED')
        report={**LIMITS,'status':'SYNTHETIC_PHYSICAL_COMMON_CUT33_PASS','schema':SCHEMA,
            'sqlReadinessProbeAttempts':len(readiness),'fixtureCoordinatedPhysicalPitrQualified':True,'fixtureS3ReadOnlyFenceQualified':True,
            'fixturePersistentSqlFenceAfterPromotion':True,'allAcknowledgementsPreserved':True,
            'ambiguousEffectReconciledWithoutResend':True,'namedTargetDistinguishedFromEndOfWal':True,
            'excludedPostTargetObjectAcknowledgements':0,'missingRequiredWalBlocksS3Start':True,
            'sourceSystemIdentifier':source_id,'restoredSystemIdentifier':restored_id,
            'targetName':TARGET,'targetLsn':target_lsn,'targetWalSegment':target_segment,
            'commonCutSha256':pitr.native.digest(proof/'common-cut.json'),
            'ociManifestDigest':bound['lock']['image']['manifestDigest'],'postgresVersion':pitr.native.VERSION,
            's3ObjectsReconciled':len(common.BODIES),'s3ObjectBytesReadPerPass':sum(map(len,common.BODIES.values())),
            's3DeniedMutations':len(observed['denied'])+len(reread['denied']),
            'cleanContainerStops':12,'cleanPostgresStops':2,'failedRecoveryProcessesTerminated':1,
            'basebackupFiles':len(base_inventory),'walArchiveFiles':len(wal_inventory),'coldBackupFiles':len(storage_inventory),
            'backupArchives':{n:pitr.native.digest(proof/(n+'.tar.gz')) for n in ('basebackup','wal-archive','cold-backup')},
            'mutatingRetries':0,'recoveryPutRequests':0,
            'scope':'two public objects; one stopped/replaced S3 identity; quiesced named point; private-socket physical PG clone'}
    except Exception as error:
        failures.append(type(error).__name__+': '+str(error)[:512])
    finally:
        for lab in reversed(containers):
            if lab.names:
                try:lab.stop()
                except Exception as error:failures.append('storage cleanup: '+str(error)[:256])
        for lab in list(reversed(destinations))+[source_pg]:
            try:lab.stop()
            except Exception as error:failures.append('postgres cleanup: '+str(error)[:256])
        if failures:report.update(status='SYNTHETIC_PHYSICAL_COMMON_CUT33_BLOCKED',failures=failures)
        report['allStartedProcessesStopped']=all(not l.names for l in containers) and all(not l.started for l in destinations+[source_pg])
        write(proof/'receipt.json',report)
    if failures:raise RuntimeError('; '.join(failures))
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('image','pg-bin','work','cohort-receipt'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    require(os.environ.get('GITHUB_ACTIONS')=='true' and os.geteuid()!=0,'UNPRIVILEGED_ISOLATED_CI_REQUIRED')
    require(not args.work.exists() and not args.work.is_symlink(),'FRESH_WORK_REQUIRED')
    print(json.dumps(execute(args.image.resolve(),args.pg_bin.resolve(),args.work.absolute(),args.cohort_receipt.resolve())))
