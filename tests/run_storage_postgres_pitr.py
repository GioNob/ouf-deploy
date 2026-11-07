"""Physical PG17.11 basebackup/WAL named-target fixture, never target recovery."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import run_storage_postgres_fixture_native as native
from storage_pitr_archive import WAL_NAME,read_regular

TARGET='ouf_fixture_before_later_ack'
MAX_TREE_BYTES=256*1024*1024
MAX_TREE_FILES=3000
LIMITS={k:False for k in ('targetPitrQualified','coordinatedS3RecoveryQualified','writerFenceQualified',
 'zeroAcknowledgedLossPolicyQualified','rpoMeasured','rtoMeasured','releaseAdmitted','runtimeAuthorityIssued')}
LIMITS.update(targetOperations=0,gatesClosed=0,acceptanceTestsPassed=0)


def require(ok,code):
 if not ok:raise RuntimeError(code)


def write(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def safe_path(path):
 value=str(path.resolve());require(re.fullmatch(r'/[A-Za-z0-9_./-]+',value),'FIXTURE_SHELL_PATH_REQUIRED');return value


def command(proof,label,argv,*,timeout=30,allow_failure=False):
 result=native.run(argv,timeout=timeout)
 (proof/(label+'.stdout')).write_bytes(result.stdout);(proof/(label+'.stderr')).write_bytes(result.stderr)
 if not allow_failure:require(result.returncode==0,'COMMAND_FAILED:'+label)
 return result


def sql(lab,statement):return lab.sql("SET statement_timeout='5s'; "+statement).stdout.decode().strip()


def snapshot(lab):
 return json.loads(sql(lab,"SELECT json_agg(row_to_json(t) ORDER BY sequence) FROM ouf_pitr_lab.records t;"))


def inventory(root):
 result={};size=0
 for path in sorted(root.rglob('*')):
  require(not path.is_symlink(),'BACKUP_SYMLINK_DENIED')
  if path.is_dir():continue
  require(path.is_file(),'REGULAR_BACKUP_MEMBER_REQUIRED');size+=path.stat().st_size
  require(size<=MAX_TREE_BYTES and len(result)<MAX_TREE_FILES,'BACKUP_TREE_BUDGET')
  result[str(path.relative_to(root))]={'bytes':path.stat().st_size,'sha256':native.digest(path)}
 require(result,'NONEMPTY_BACKUP_REQUIRED');return result


def package(root,destination):
 entries=inventory(root)
 with destination.open('xb') as raw,gzip.GzipFile(fileobj=raw,mode='wb',mtime=0) as compressed,tarfile.open(fileobj=compressed,mode='w|') as archive:
  for name in sorted(entries):
   path=root/name;info=tarfile.TarInfo(name);info.size=path.stat().st_size;info.mode=0o600;info.mtime=0
   with path.open('rb') as stream:archive.addfile(info,stream)
 require(inventory(root)==entries,'BACKUP_CHANGED_DURING_PACKAGING');return entries


def archive_command(mode,archive,eventlog):
 return ' '.join([safe_path(Path(sys.executable)),'-I -B -S',safe_path(ROOT/'tests/storage_pitr_archive.py'),mode,safe_path(archive),'%p','%f',safe_path(eventlog)])


def append_settings(data,settings):
 with (data/'postgresql.conf').open('a') as stream:stream.write('\n'+settings+'\n')


def restart_source(source,proof):
 command(proof,'enable-archiving',[str(source.binary('pg_ctl')),'-D',str(source.data),'-m','fast','-l',str(source.output/'postgres.log'),'-w','-t','20','restart'],timeout=25)


def restore_lab(pg_bin,base,archive,work,proof,label):
 destination=native.NativeLab(pg_bin,proof/label);destination.output.mkdir()
 destination.data=work/(label+'-data');shutil.copytree(base,destination.data)
 destination.socket=work/(label+'-socket');destination.socket.mkdir(mode=0o700)
 require(destination.data.resolve()!=base.resolve(),'INDEPENDENT_RESTORE_ROOT_REQUIRED')
 append_settings(destination.data,
  "listen_addresses = ''\nport = %d\nunix_socket_directories = '%s'\nunix_socket_permissions = 0700\n"
  "archive_mode = off\narchive_command = ''\nrestore_command = '%s'\n"
  "recovery_target_timeline = '1'\nrecovery_target_name = '%s'\nrecovery_target_action = 'pause'\n"
  "hot_standby = on\n"%(native.PORT,safe_path(destination.socket),archive_command('restore',archive,proof/(label+'-wal-events.jsonl')),TARGET))
 (destination.data/'recovery.signal').write_bytes(b'')
 destination.started=True
 return destination


def start_restore(destination,proof,label):
 return command(proof,label+'-start',[str(destination.binary('pg_ctl')),'-D',str(destination.data),'-l',str(destination.output/'postgres.log'),'-w','-t','15','start'],timeout=20,allow_failure=True)


def stop_failed_restore(destination,proof):
 deadline=time.monotonic()+10;attempt=0
 while True:
  attempt+=1
  status=command(proof,'missing-wal-process-status-%02d'%attempt,[str(destination.binary('pg_ctl')),'-D',str(destination.data),'status'],timeout=3,allow_failure=True)
  if status.returncode==3:break
  require(status.returncode==0 and time.monotonic()<deadline,'MISSING_WAL_SERVER_MUST_STOP_WITHIN_BUDGET');time.sleep(0.1)
 destination.started=False


def exercise(pg_bin,output,proof,work,source,destinations):
 identities={}
 for name in ('pg_basebackup','pg_verifybackup','pg_waldump'):
  binary=pg_bin/name;r=command(proof,name+'-version',[str(binary),'--version'])
  require(r.stdout.decode().strip().endswith(' '+native.VERSION),'PINNED_POSTGRES_TOOL_REQUIRED')
  identities[name]={'version':r.stdout.decode().strip(),'sha256':native.digest(binary)}
 write(proof/'backup-tool-identities.json',identities)
 source.start(initialize_catalog=False)
 source_id=sql(source,'SELECT system_identifier FROM pg_control_system();')
 require(source_id.isdecimal(),'POSTGRES_SYSTEM_IDENTIFIER_REQUIRED')
 archive=work/'wal-archive';archive.mkdir(mode=0o700)
 append_settings(source.data,"wal_level = replica\nfull_page_writes = on\narchive_mode = on\narchive_command = '%s'\n"%archive_command('archive',archive,proof/'archive-events.jsonl'))
 restart_source(source,proof)
 require(sql(source,'SHOW wal_segment_size;')=='16MB' and sql(source,'SHOW archive_mode;')=='on','EXPECTED_WAL_CONFIGURATION_REQUIRED')
 sql(source,"CREATE SCHEMA ouf_pitr_lab; CREATE TABLE ouf_pitr_lab.records(sequence integer PRIMARY KEY,value text NOT NULL); INSERT INTO ouf_pitr_lab.records VALUES(1,'base-ack');")
 base=work/'basebackup'
 command(proof,'basebackup',[str(pg_bin/'pg_basebackup'),'--pgdata='+str(base),'--host='+str(source.socket),'--port='+str(native.PORT),'--username=fixture_admin','--no-password','--checkpoint=fast','--wal-method=stream','--manifest-checksums=SHA256','--label=ouf-synthetic-pitr'],timeout=90)
 command(proof,'verifybackup',[str(pg_bin/'pg_verifybackup'),str(base)],timeout=60)
 base_inventory=inventory(base);write(proof/'basebackup-inventory.json',base_inventory)
 # Ensure the target record will require a segment newer than the basebackup.
 sql(source,'CHECKPOINT; SELECT pg_switch_wal();')
 sql(source,"INSERT INTO ouf_pitr_lab.records VALUES(2,'before-target-ack');")
 expected=snapshot(source);write(proof/'expected-at-target.json',expected)
 target_lsn=sql(source,"SELECT pg_create_restore_point('%s');"%TARGET)
 require(re.fullmatch(r'[0-9A-F]+/[0-9A-F]+',target_lsn),'RESTORE_POINT_LSN_REQUIRED')
 target_segment=sql(source,"SELECT pg_walfile_name('%s'::pg_lsn);"%target_lsn)
 require(re.fullmatch(r'[0-9A-F]{24}',target_segment) and 'pg_wal/'+target_segment not in base_inventory,'POST_BASE_WAL_SEGMENT_REQUIRED')
 sql(source,"INSERT INTO ouf_pitr_lab.records VALUES(3,'ack-after-selected-target');")
 latest=snapshot(source);write(proof/'source-after-target.json',latest)
 sql(source,'SELECT pg_switch_wal();')
 deadline=time.monotonic()+15
 while not (archive/target_segment).is_file():
  require(time.monotonic()<deadline,'TARGET_WAL_ARCHIVE_TIMEOUT');time.sleep(0.1)
 require(read_regular(archive/target_segment)==read_regular(source.data/'pg_wal'/target_segment),'ARCHIVED_TARGET_SEGMENT_MISMATCH')
 # Withhold the source process and data before the independent recovery.
 source.stop();require(not source.started,'SOURCE_STOP_REQUIRED')
 archived_inventory=inventory(archive);write(proof/'wal-archive-inventory.json',archived_inventory)
 package(base,proof/'basebackup.tar.gz');package(archive,proof/'wal-archive.tar.gz')
 restore=restore_lab(pg_bin,base,archive,work,proof,'restored');destinations.append(restore)
 require(start_restore(restore,proof,'restored').returncode==0,'RESTORE_START_REQUIRED')
 deadline=time.monotonic()+15
 while sql(restore,'SELECT pg_is_in_recovery() AND pg_is_wal_replay_paused();')!='t':
  require(time.monotonic()<deadline,'TARGET_PAUSE_TIMEOUT');time.sleep(0.1)
 restored_id=sql(restore,'SELECT system_identifier FROM pg_control_system();')
 require(restored_id==source_id,'PHYSICAL_BACKUP_SYSTEM_IDENTITY_REQUIRED')
 observed=snapshot(restore);write(proof/'restored-at-target.json',observed)
 require(observed==expected and [r['sequence'] for r in observed]==[1,2] and [r['sequence'] for r in latest]==[1,2,3],'NAMED_TARGET_ROWS_REQUIRED')
 require(sql(restore,'SHOW listen_addresses;')=='','PRIVATE_SOCKET_ONLY_REQUIRED')
 replay_lsn=sql(restore,'SELECT pg_last_wal_replay_lsn();')
 events=[json.loads(line) for line in (proof/'restored-wal-events.jsonl').read_text().splitlines()]
 reads=[e for e in events if e['name']==target_segment and e['status']=='COPIED']
 require(reads and all(e['sha256']==archived_inventory[target_segment]['sha256'] for e in reads),'POST_BASE_ARCHIVE_READ_REQUIRED')
 restore.stop()
 # A second fresh basebackup copy lacks the required post-base segment.
 incomplete=work/'incomplete-archive';shutil.copytree(archive,incomplete);(incomplete/target_segment).unlink()
 negative=restore_lab(pg_bin,base,incomplete,work,proof,'missing-wal');destinations.append(negative)
 # Do not expose a temporary read-only readiness window before target failure.
 append_settings(negative.data,"hot_standby = off\n")
 failure=start_restore(negative,proof,'missing-wal')
 # pg_ctl may observe transient startup state; terminal failure is authoritative.
 stop_failed_restore(negative,proof)
 negative_log=(negative.output/'postgres.log').read_text()
 require('recovery ended before configured recovery target was reached' in negative_log,'MISSING_TARGET_WAL_FAILURE_REQUIRED')
 missing_events=[json.loads(line) for line in (proof/'missing-wal-wal-events.jsonl').read_text().splitlines()]
 require(any(e['name']==target_segment and e['status']=='MISSING' for e in missing_events),'MISSING_TARGET_WAL_OBSERVED_REQUIRED')
 require(inventory(base)==base_inventory and inventory(archive)==archived_inventory,'ORIGINAL_BACKUP_CUSTODY_REQUIRED')
 return {**LIMITS,'schema':'ouf.storage-postgres-physical-pitr-fixture.v1','status':'NATIVE_SYNTHETIC_PHYSICAL_PITR_PASS','postgresVersion':native.VERSION,'physicalBaseBackupVerified':True,'postBaseWalSegmentReplayed':True,'namedRecoveryTargetPaused':True,'targetName':TARGET,'targetLsn':target_lsn,'observedReplayLsn':replay_lsn,'targetWalSegment':target_segment,'sourceSystemIdentifier':source_id,'restoredSystemIdentifier':restored_id,'sameSystemIdentifierExpectedForPhysicalBackup':True,'separateDataDirectories':True,'sourceStoppedBeforeRestore':True,'basebackupFiles':len(base_inventory),'basebackupBytes':sum(x['bytes'] for x in base_inventory.values()),'archivedFiles':len(archived_inventory),'archivedBytes':sum(x['bytes'] for x in archived_inventory.values()),'expectedRowsAtTarget':2,'sourceRowsAfterTarget':3,'deliberatelyExcludedPostTargetAcknowledgedRows':1,'postTargetRowRetainedInSourceEvidence':True,'missingRequiredWalRejected':True,'negativePgCtlStartReturnCode':failure.returncode,'basebackupArchiveSha256':native.digest(proof/'basebackup.tar.gz'),'walArchiveSha256':native.digest(proof/'wal-archive.tar.gz'),'boundary':'Selected older synthetic point excludes a later acknowledged row deliberately. This is not zero-loss recovery, a production RPO policy or coordinated S3 recovery.'}


def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--pg-bin',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
 require(os.geteuid()!=0,'UNPRIVILEGED_LAB_USER_REQUIRED');output=args.output.resolve();require(not output.exists() and not output.is_symlink(),'FRESH_OUTPUT_REQUIRED');output.mkdir(parents=True,mode=0o700)
 proof=output/'evidence';proof.mkdir();work=output/'work';work.mkdir();source=native.NativeLab(args.pg_bin,proof/'source');destinations=[];receipt={**LIMITS,'status':'NATIVE_SYNTHETIC_PHYSICAL_PITR_BLOCKED'};failures=[]
 try:receipt=exercise(args.pg_bin.resolve(),output,proof,work,source,destinations)
 except Exception as error:failures.append(type(error).__name__+': '+str(error))
 finally:
  for lab in list(reversed(destinations))+[source]:
   try:lab.stop()
   except Exception as error:failures.append('cleanup: '+type(error).__name__+': '+str(error))
  if failures:receipt.update(status='NATIVE_SYNTHETIC_PHYSICAL_PITR_BLOCKED',failures=failures)
  receipt['allStartedProcessesStopped']=all(not lab.started for lab in destinations+[source]);write(proof/'receipt.json',receipt)
 print(json.dumps(receipt));return 1 if failures else 0

if __name__=='__main__':raise SystemExit(main())
