#!/usr/bin/env python3
"""Independent readback of the original native ZIP, without running a second lab."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import zipfile

def sha(raw):return hashlib.sha256(raw).hexdigest()
def require(ok,message):
    if not ok:raise ValueError(message)

def verify(archive, source, expected_sha, producer):
    raw=archive.read_bytes();require(sha(raw)==expected_sha,'ORIGINAL_ARCHIVE_DIGEST')
    with zipfile.ZipFile(archive) as z:
        entries=z.infolist();names=[x.filename for x in entries]
        require(len(names)==len(set(names)) and len(names)<=2000,'UNIQUE_BOUNDED_MEMBERS')
        require(sum(x.file_size for x in entries)<=64*1024*1024,'BOUNDED_UNCOMPRESSED_BYTES')
        for name in names:
            p=PurePosixPath(name);require(not p.is_absolute() and '..' not in p.parts and '\\' not in name,'SAFE_ARCHIVE_PATH')
        payload={x.filename:z.read(x) for x in entries if not x.is_dir()}
    checks={}
    for line in payload['SHA256SUMS'].decode().splitlines():
        digest,name=line.split('  ',1);require(name not in checks,'UNIQUE_CHECKSUM');checks[name]=digest
    require(set(checks)==set(payload)-{'SHA256SUMS'},'EXHAUSTIVE_ARCHIVE_CHECKSUMS')
    for name,digest in checks.items():require(sha(payload[name])==digest,'MEMBER_CHECKSUM: '+name)
    require(payload['source-commit.txt'].decode().strip()==producer,'EXACT_PRODUCER')
    bindings=json.loads(payload['source-sha256.json'])
    require(len(bindings)==40 and 'scripts/storage-generation33-markeronly-crash.py' in bindings and 'tests/test_storage_markeronly_crash_generation33.py' in bindings and 'scripts/storage-generation33-interrename-crash.py' in bindings and 'tests/test_storage_interrename_crash_generation33.py' in bindings,'COMPLETE_INTERRENAME_SOURCE_BINDINGS')
    for path,digest in bindings.items():require(sha((source/path).read_bytes())==digest,'EXACT_SOURCE: '+path)
    def read(path):return json.loads(payload[path])
    labs=['lab','crash-lab','filer-crash-lab','master-crash-lab','all-crash-lab','stream-lab','cleanup-lab',
          'compaction-lab','compaction-restart-lab','relocation-lab','compaction-crash-lab','commit-crash-lab','interrename-crash-lab','markeronly-crash-lab']
    summaries={name:read(name+'/receipt.json') for name in labs}
    for name,r in summaries.items():
        require(r['status']=='SYNTHETIC_ROLE_NETWORK_ISOLATION_PASS','NATIVE_SCENARIO_PASS: '+name)
        require(r['networkRemoved'] and r['retainedNamespacePinsReleased'] and r['cleanContainerStops']==5,'NATIVE_CLEANUP: '+name)
        require(r['targetOperations']==r['gatesClosed']==r['acceptanceTestsPassed']==r['mutatingRequestRetries']==0,'UNCHANGED_AUTHORITY_AND_RETRIES')
    stopped=[read(name) for name in payload if name.endswith('-stopped.json')]
    require(len(stopped)==70 and all(not x['Running'] and x['ExitCode']==0 and not x['OOMKilled'] for x in stopped),'ALL_70_CLEAN_FINAL_STOPS')
    base='compaction-crash-lab/'
    def get(name):return read(base+name+'.json')
    frozen=get('precommit-freeze');recovered=get('precommit-recovery')
    require(frozen['status']=='OBSERVED_PRECOMMIT_FROZEN' and recovered['status']=='PRECOMMIT_PROCESS_CRASH_RECOVERY_PASS','OBSERVED_AND_RECOVERED_PHASE')
    require(frozen['processBefore']==frozen['processFrozen'],'PROCESS_IDENTITY')
    require(frozen['threadStates'] and set(frozen['threadStates'].values())=={'T'},'ALL_TASKS_STOPPED')
    files=frozen['filesFrozen'];before=frozen['filesBefore']
    require(set(before)=={'.dat','.idx'} and '.cpc' not in files,'NO_MARKER_OR_STALE_WORK')
    require(8<files['.cpd']['bytes']<before['.dat']['bytes'],'COPY_OBSERVED')
    require(all(files[ext]==before[ext] for ext in before),'NO_ORIGINAL_CHANGE_OR_RENAME')
    for ext in ('.cpd','.cpx'):
        if ext in files:
            data=payload[base+'precommit-retained'+ext]
            require(len(data)==files[ext]['bytes'] and sha(data)==files[ext]['sha256'],'ORIGINAL_TEMPORARY_BYTES')
    require(files==get('precommit-stopped-files')==get('precommit-gated-files'),'FROZEN_STOPPED_GATED_IDENTICAL')
    snapshots={n:get(n) for n in ('compaction-before','precommit-frozen-dat','post-compaction-gated-dat','post-compaction-recovered-dat','post-compaction-final-dat')}
    for key in ('datFiles','indexes','datBytes','datAllocatedBytes','orphanPayloadFiles'):
        require(all(v[key]==snapshots['compaction-before'][key] for v in snapshots.values()),'ROLLBACK_DAT_IDX_AND_ALLOCATION: '+key)
    for name in ('post-compaction-recovered-dat','post-compaction-final-dat'):
        require(not snapshots[name]['temporaryCompactionFiles'] and not snapshots[name]['openDeletedFixtureFiles'],'RECOVERY_REMOVES_TEMPORARIES')
    witness=get('relocation-before-compaction')
    require(witness==get('precommit-frozen-witness')==get('relocation-after-restart'),'WITNESS_BODY_IDENTITY_AND_OFFSET')
    require(get('relocation-read-before-compaction')==get('relocation-read-after-restart'),'NATIVE_GET_PARITY')
    require(get('compaction-metadata-before')==get('post-compaction-metadata'),'FULL_FILER_METADATA_PARITY')
    recovery=get('post-compaction-recovery')
    require(get('post-compaction-final-read')==summaries['compaction-crash-lab']['object'],'FINAL_S3_NATIVE_SUMMARY_PARITY')
    require(recovery['baselineS3Parity'] and recovery['s3ObjectAbsent'] and recovery['directChunk404'],'S3_BASELINE_AND_ORPHAN_ABSENCE')
    require(recovery['additionalVacuumCommands']==recovery['recoveryPutRequests']==recovery['mutatingRetries']==0,'NO_MUTATING_RESEND')
    killed=get('post-compaction-killed');roles=get('post-compaction-before-crash')
    require(set(killed)=={'master','volume','filer','s3'},'ALL_FOUR_SERVICES_KILLED')
    for role,v in killed.items():
        require(v['Id']==roles[role]['Id'] and v['State']['ExitCode']==137 and not v['State']['OOMKilled'] and not v['State']['Running'],'EXACT_SIGKILL_DEATH')
    require(frozen['processBefore']['pid']==roles['volume']['State']['Pid'] and roles['volume']['Id'] in frozen['processBefore']['cgroup'],'OBSERVER_CONTAINER_BINDING')
    require(get('compaction-execution')['vacuumCommands']==1 and get('compaction-execution')['terminatedBeforeRecovery'],'SINGLE_TERMINATED_VACUUM')
    probes=get('post-compaction-role-probes');dns=get('post-compaction-dns-host-probes')
    require(sum(x['allowed'] for x in probes)==11 and len(dns)==15,'COMPLETE_NETWORK_MATRIX')
    for x in probes:
        require(x['connected'] if x['allowed'] else not x['connected'] and x['counterAfter']>x['counterBefore'],'ROLE_PROBE_EVIDENCE')
    require(all(not x['connected'] and x['counterAfter']>x['counterBefore'] for x in dns),'DNS_HOST_DENIAL_EVIDENCE')
    source_binding=read('compaction-source/source-binding.json')
    require(source_binding['binarySha256']==frozen['binarySha256'] and not source_binding['instrumentedBuild'],'EXACT_UNINSTRUMENTED_BINARY')
    for path,digest in source_binding['reviewedUnmodifiedSourceSha256'].items():
        require(sha(payload['compaction-source/'+path.replace('/','__')])==digest,'RETAINED_REVIEWED_SOURCE')
    # Independent reconstruction of the second crash phase from retained bytes.
    def pm(name):return read('commit-crash-lab/'+name+'.json')
    phase=pm('postmarker-freeze');done=pm('postmarker-recovery')
    require(phase['status']=='OBSERVED_POSTMARKER_FROZEN' and done['status']=='POSTMARKER_PROCESS_CRASH_RECOVERY_PASS','POSTMARKER_OBSERVED_AND_RECOVERED')
    require(phase['processBefore']==phase['processFrozen'] and phase['binarySha256']==source_binding['binarySha256'],'POSTMARKER_EXACT_PROCESS_BINARY')
    require(phase['threadStates'] and set(phase['threadStates'].values())=={'t'} and str(phase['tid']) in phase['threadStates'],'ALL_POSTMARKER_THREADS_TRACED')
    require(phase['number'] in (82,264,316) and phase['operation']=='entry' and phase['syscallNotResumed'],'RENAME_ENTRY_NOT_EXECUTED')
    chunk=pm('cleanup-chunk');target=chunk['datFile'];index=target.removesuffix('.dat')+'.idx'
    require(phase['oldPath']=='/data/'+target.removesuffix('.dat')+'.cpd' and phase['newPath']=='/data/'+target,'EXACT_RENAME_PATHS')
    syncs=phase['successfulSyncs']
    require([x['kind'] for x in syncs]==['marker','directory'] and all(x['returnValue']==0 for x in syncs),'SUCCESSFUL_ORDERED_FSYNC')
    originals=phase['filesBefore'];copies=phase['filesFrozen']
    require(set(originals)=={'.dat','.idx'} and set(copies)=={'.dat','.idx','.cpd','.cpx','.cpc'},'EXACT_POSTMARKER_FILE_SET')
    require(all(copies[ext]==originals[ext] for ext in originals),'NEITHER_ORIGINAL_RENAMED')
    require(copies['.cpc']['bytes']==0 and copies['.cpc']['sha256']==sha(b''),'EMPTY_COMMIT_MARKER')
    require(8<copies['.cpd']['bytes']<originals['.dat']['bytes'] and copies['.cpx']['bytes']>0,'NONEMPTY_COMPACTED_COPIES')
    for ext in ('.cpd','.cpx','.cpc'):
        data=payload['commit-crash-lab/postmarker-retained'+ext]
        require(len(data)==copies[ext]['bytes'] and sha(data)==copies[ext]['sha256'],'RETAINED_POSTMARKER_BYTES')
    require(copies==pm('postmarker-stopped-files')==pm('postmarker-gated-files'),'POSTMARKER_FROZEN_STOPPED_GATED_IDENTICAL')
    live=pm('postmarker-recovered-files')
    require(set(live)=={'.dat','.idx'} and live['.dat']==copies['.cpd'] and live['.idx']==copies['.cpx'],'EXACT_TEMPORARY_INODES_PROMOTED')
    require(live==pm('postmarker-final-files'),'ROLLED_FORWARD_PAIR_PERSISTS_AFTER_PROBES')
    snaps={n:pm(n) for n in ('compaction-before','postmarker-frozen-dat','post-compaction-gated-dat','post-compaction-recovered-dat','post-compaction-final-dat')}
    old=snaps['compaction-before'];new=snaps['post-compaction-recovered-dat']
    for key in ('datFiles','indexes','datBytes','datAllocatedBytes','orphanPayloadFiles'):
        require(old[key]==snaps['postmarker-frozen-dat'][key]==snaps['post-compaction-gated-dat'][key],'OLD_STORAGE_BEFORE_EXEC: '+key)
    require(new==snaps['post-compaction-final-dat'],'RECOVERY_STORAGE_STABLE')
    require(old['orphanPayloadFiles']==[target] and not new['orphanPayloadFiles'] and not new['temporaryCompactionFiles'] and not new['openDeletedFixtureFiles'],'ROLLFORWARD_REMOVES_ORPHAN_AND_TEMPORARIES')
    require(set(old['datFiles'])==set(new['datFiles']) and set(old['indexes'])==set(new['indexes']),'UNCHANGED_VOLUME_SET')
    require(chunk['needleId'] in old['indexes'][index]['deletedNeedles'] and chunk['needleId'] not in new['indexes'][index]['deletedNeedles'] and str(chunk['needleId']) not in new['indexes'][index]['liveNeedles'],'ORPHAN_INDEX_PHYSICALLY_REMOVED')
    for name in old['datFiles']:
        idx=name.removesuffix('.dat')+'.idx'
        require(old['indexes'][idx]['liveNeedles']==new['indexes'][idx]['liveNeedles'],'EVERY_LIVE_NEEDLE_PRESERVED')
        if name!=target:require(old['datFiles'][name]==new['datFiles'][name] and old['indexes'][idx]==new['indexes'][idx],'UNSELECTED_VOLUME_EXACT')
    reclaimed=old['datBytes']-new['datBytes'];allocated=old['datAllocatedBytes']-new['datAllocatedBytes']
    require(reclaimed>=4194304 and allocated>=4194304,'ACTUAL_LENGTH_AND_BLOCK_RECLAIM')
    witness_old=pm('relocation-before-compaction');witness_new=pm('postmarker-recovered-witness')
    require(witness_old==pm('postmarker-frozen-witness') and witness_new==pm('relocation-after-restart'),'WITNESS_FREEZE_AND_RECOVERY_STABILITY')
    for key in ('volumeId','datFile','needleId','cookieHex','fileId','dataBytes','dataSha256','needleSize'):
        require(witness_old[key]==witness_new[key],'RELOCATED_WITNESS_IDENTITY: '+key)
    require(witness_new['needleOffset']>=8 and witness_new['needleOffset']%8==0 and witness_old['needleOffset']-witness_new['needleOffset']==reclaimed and witness_old['datBytes']-witness_new['datBytes']==reclaimed,'WITNESS_REAL_RELOCATION')
    require(pm('relocation-read-before-compaction')==pm('relocation-read-after-restart'),'POSTMARKER_NATIVE_GET_PARITY')
    require(pm('compaction-metadata-before')==pm('post-compaction-metadata'),'POSTMARKER_FULL_METADATA_PARITY')
    pm_recovery=pm('post-compaction-recovery');pm_roles=pm('post-compaction-before-crash');pm_killed=pm('post-compaction-killed')
    require(set(pm_killed)=={'master','volume','filer','s3'},'POSTMARKER_FOUR_KILLED')
    for role,v in pm_killed.items():
        require(v['Id']==pm_roles[role]['Id'] and v['State']['ExitCode']==137 and not v['State']['OOMKilled'] and not v['State']['Running'],'POSTMARKER_SIGKILL_EXACT')
    require(phase['processBefore']['pid']==pm_roles['volume']['State']['Pid'] and pm_roles['volume']['Id'] in phase['processBefore']['cgroup'],'POSTMARKER_CONTAINER_BINDING')
    exits=pm('postmarker-observer-exit')
    require(exits['status']=='ALL_TRACED_THREADS_KILLED' and {str(x['tid']) for x in exits['exits']}==set(phase['threadStates']) and all(x['signal']==9 for x in exits['exits']),'ALL_FROZEN_THREADS_DIED_WITHOUT_RESUME')
    require(pm('compaction-execution')['vacuumCommands']==1 and pm('compaction-execution')['terminatedBeforeRecovery'],'POSTMARKER_SINGLE_VACUUM')
    require(pm_recovery['additionalVacuumCommands']==pm_recovery['recoveryPutRequests']==pm_recovery['mutatingRetries']==0,'POSTMARKER_NO_RESEND')
    require(pm_recovery['baselineS3Parity'] and pm_recovery['s3ObjectAbsent'] and pm_recovery['directChunk404'],'POSTMARKER_BASELINE_AND_ABSENCE')
    require(pm('post-compaction-final-read')==summaries['commit-crash-lab']['object'],'POSTMARKER_FINAL_READ_PARITY')
    require(pm_recovery['filerResponseBytesAfter']>pm_recovery['filerResponseBytesBefore'] and pm_recovery['volumeResponseBytesAfter']-pm_recovery['volumeResponseBytesBefore']>=8388865,'POSTMARKER_REAL_NETWORK_BYTES')
    pm_probes=pm('post-compaction-role-probes');pm_dns=pm('post-compaction-dns-host-probes')
    require(sum(x['allowed'] for x in pm_probes)==11 and len(pm_probes)==32 and len(pm_dns)==15,'POSTMARKER_MATRIX_SIZE')
    for x in pm_probes:require(x['connected'] if x['allowed'] else not x['connected'] and x['counterAfter']>x['counterBefore'],'POSTMARKER_ROLE_PROBE')
    require(all(not x['connected'] and x['counterAfter']>x['counterBefore'] for x in pm_dns),'POSTMARKER_DNS_HOST_PROBE')

    # Reconstruct the mixed pair and final promotion directly from retained bytes.
    def ir(name):return read('interrename-crash-lab/'+name+'.json')
    mixed_phase=ir('interrename-freeze');mixed_done=ir('interrename-recovery')
    require(mixed_phase['status']=='OBSERVED_INTERRENAME_FROZEN' and mixed_done['status']=='INTERRENAME_PROCESS_CRASH_RECOVERY_PASS','INTERRENAME_PHASE_AND_RECOVERY')
    require(mixed_phase['processBefore']==mixed_phase['processFrozen'] and mixed_phase['binarySha256']==source_binding['binarySha256'],'INTERRENAME_PROCESS_AND_BINARY')
    require(mixed_phase['threadStates'] and set(mixed_phase['threadStates'].values())=={'t'} and str(mixed_phase['tid']) in mixed_phase['threadStates'],'ALL_MIXED_THREADS_STOPPED')
    ir_chunk=ir('cleanup-chunk');ir_target=ir_chunk['datFile'];ir_index=ir_target.removesuffix('.dat')+'.idx'
    stem='/data/'+ir_target.removesuffix('.dat')
    first=mixed_phase['beforeDatRenamePhase'];first_files=mixed_phase['filesBeforeDatRename']
    before_files=mixed_phase['filesBefore'];mixed_files=mixed_phase['filesFrozen'];first_exit=mixed_phase['firstRenameResult']
    require(first['operation']=='entry' and first['syscallNotResumed'] and first['oldPath']==stem+'.cpd' and first['newPath']==stem+'.dat' and first['number'] in (82,264,316),'EXACT_FIRST_RENAME_ENTRY')
    require(first['threadStates'] and set(first['threadStates'].values())=={'t'},'ALL_THREADS_STOPPED_FOR_FIRST_COPY_CAPTURE')
    require([x['kind'] for x in first['successfulSyncs']]==['marker','directory'] and all(x['returnValue']==0 for x in first['successfulSyncs']),'INTERRENAME_MARKER_DIRECTORY_SYNC')
    require(first_exit['operation']=='exit' and first_exit['returnValue']==0 and not first_exit['isError'] and first_exit['tid']==first['tid'] and first_exit['number']==first['number'] and first_exit['oldPath']==first['oldPath'] and first_exit['newPath']==first['newPath'],'FIRST_RENAME_EXECUTED_SUCCESSFULLY')
    require(mixed_phase['operation']=='entry' and mixed_phase['syscallNotResumed'] and mixed_phase['number'] in (82,264,316) and mixed_phase['oldPath']==stem+'.cpx' and mixed_phase['newPath']==stem+'.idx','EXACT_SECOND_RENAME_ENTRY_NOT_RESUMED')
    require(set(before_files)=={'.dat','.idx'} and set(first_files)=={'.dat','.idx','.cpd','.cpx','.cpc'} and set(mixed_files)=={'.dat','.idx','.cpx','.cpc'},'EXACT_MIXED_FILE_SETS')
    require(all(first_files[ext]==before_files[ext] for ext in before_files),'OLD_PAIR_BEFORE_FIRST_RENAME')
    require(first_files['.cpc']['bytes']==0 and first_files['.cpc']['sha256']==sha(b''),'INTERRENAME_EMPTY_MARKER')
    require(mixed_files['.dat']==first_files['.cpd'] and mixed_files['.dat']!=before_files['.dat'] and mixed_files['.idx']==before_files['.idx'],'NEW_DAT_OLD_IDX_EXACT_INODES')
    require(all(mixed_files[ext]==first_files[ext] for ext in ('.cpx','.cpc')),'PENDING_IDX_AND_MARKER_PRESERVED')
    for prefix,files,extensions in [('interrename-before-dat-retained',first_files,('.cpd','.cpx','.cpc','.idx')),('interrename-frozen-retained',mixed_files,('.dat','.idx','.cpx','.cpc'))]:
        for ext in extensions:
            data=payload['interrename-crash-lab/'+prefix+ext]
            require(len(data)==files[ext]['bytes'] and sha(data)==files[ext]['sha256'],'RETAINED_INTERRENAME_BYTES')
    require(mixed_files==ir('interrename-stopped-files')==ir('interrename-gated-files'),'MIXED_FILES_IDENTICAL_UNTIL_EXEC')
    raw_before=mixed_phase['rawStorageBefore'];raw_mixed=mixed_phase['rawStorageFrozen']
    require(raw_mixed==ir('interrename-frozen-storage')==ir('interrename-gated-storage'),'ALL_RAW_FILES_IDENTICAL_UNTIL_EXEC')
    require(set(raw_before)==set(raw_mixed) and raw_before[ir_target]==before_files and raw_mixed[ir_target]==mixed_files,'MIXED_RAW_SNAPSHOT_BINDING')
    require(all(raw_before[n]==raw_mixed[n] for n in raw_before if n!=ir_target),'MIXED_UNSELECTED_FILES_IDENTICAL')
    ir_live=ir('interrename-listeners-ready-files')
    require(set(ir_live)=={'.dat','.idx'} and ir_live['.dat']==mixed_files['.dat'] and ir_live['.idx']==mixed_files['.cpx'],'EXACT_PAIR_COHERENT_AT_FIRST_READINESS')
    require(ir_live==ir('interrename-recovered-files')==ir('interrename-final-files'),'RECOVERED_PAIR_PERSISTS')
    ir_old=ir('compaction-before');ir_new=ir('interrename-listeners-ready-dat')
    require(ir_new==ir('post-compaction-recovered-dat')==ir('post-compaction-final-dat'),'STORAGE_COHERENT_BEFORE_AND_AFTER_FIXTURE_READS')
    require(ir_old['orphanPayloadFiles']==[ir_target] and not ir_new['orphanPayloadFiles'] and not ir_new['temporaryCompactionFiles'] and not ir_new['openDeletedFixtureFiles'],'INTERRENAME_ORPHAN_AND_TEMP_REMOVED')
    require(set(ir_old['datFiles'])==set(ir_new['datFiles']) and set(ir_old['indexes'])==set(ir_new['indexes']),'INTERRENAME_VOLUME_SET_UNCHANGED')
    require(ir_chunk['needleId'] in ir_old['indexes'][ir_index]['deletedNeedles'] and ir_chunk['needleId'] not in ir_new['indexes'][ir_index]['deletedNeedles'] and str(ir_chunk['needleId']) not in ir_new['indexes'][ir_index]['liveNeedles'],'INTERRENAME_ORPHAN_INDEX_REMOVED')
    for name in ir_old['datFiles']:
        idx=name.removesuffix('.dat')+'.idx'
        require(ir_old['indexes'][idx]['liveNeedles']==ir_new['indexes'][idx]['liveNeedles'],'INTERRENAME_ALL_LIVE_NEEDLES')
        require(all(raw_before[name]['.dat'][key]==ir_old['datFiles'][name][key] for key in ('bytes','allocatedBytes','sha256')) and all(raw_before[name]['.idx'][key]==ir_old['indexes'][idx][key] for key in ('bytes','sha256')),'INTERRENAME_BASELINE_BOUND')
        if name!=ir_target:require(ir_old['datFiles'][name]==ir_new['datFiles'][name] and ir_old['indexes'][idx]==ir_new['indexes'][idx],'INTERRENAME_UNSELECTED_VOLUMES_PRESERVED')
    ir_reclaimed=ir_old['datBytes']-ir_new['datBytes'];ir_allocated=ir_old['datAllocatedBytes']-ir_new['datAllocatedBytes']
    require(ir_reclaimed>=4194304 and ir_allocated>=4194304,'INTERRENAME_REAL_SPACE_RECOVERED')
    ir_witness_old=ir('relocation-before-compaction');ir_witness_new=ir('interrename-listeners-ready-witness')
    require(ir_witness_old==mixed_phase['witnessBeforeDatRename'],'WITNESS_EXACT_BEFORE_DAT_RENAME')
    require(ir_witness_new==ir('interrename-recovered-witness')==ir('relocation-after-restart'),'WITNESS_COHERENT_FROM_FIRST_READINESS')
    for key in ('volumeId','datFile','needleId','cookieHex','fileId','dataBytes','dataSha256','needleSize'):
        require(ir_witness_old[key]==ir_witness_new[key],'INTERRENAME_WITNESS_IDENTITY: '+key)
    require(ir_witness_new['needleOffset']>=8 and ir_witness_new['needleOffset']%8==0 and ir_witness_old['needleOffset']-ir_witness_new['needleOffset']==ir_reclaimed and ir_witness_old['datBytes']-ir_witness_new['datBytes']==ir_reclaimed,'INTERRENAME_WITNESS_RELOCATION')
    # Independent binary decoding: stale IDX offset cannot address this frozen DAT.
    import struct
    dat=payload['interrename-crash-lab/interrename-frozen-retained.dat']
    def binary_entry(extension):
        index=payload['interrename-crash-lab/interrename-frozen-retained'+extension]
        require(len(index)%16==0,'COMPLETE_RETAINED_BINARY_INDEX')
        rows=[struct.unpack('>QIi',index[p:p+16]) for p in range(0,len(index),16)]
        found=[(off*8,size) for nid,off,size in rows if nid==ir_witness_old['needleId']]
        require(len(found)==1 and found[0][1]>0,'UNIQUE_RETAINED_WITNESS_INDEX');return found[0]
    old_offset,old_size=binary_entry('.idx');new_offset,new_size=binary_entry('.cpx')
    require(old_offset==ir_witness_old['needleOffset'] and old_offset>=len(dat) and new_offset==ir_witness_new['needleOffset'] and new_offset>=8 and new_offset%8==0 and old_offset-new_offset==ir_reclaimed and new_offset+20+ir_witness_old['dataBytes']<=len(dat),'RETAINED_OLD_IDX_INVALID_NEW_IDX_VALID')
    cookie,nid,stored_size,data_size=struct.unpack('>IQiI',dat[new_offset:new_offset+20])
    require(nid==ir_witness_old['needleId'] and format(cookie,'08x')==ir_witness_old['cookieHex'] and stored_size==old_size==new_size==ir_witness_new['needleSize'] and data_size==ir_witness_old['dataBytes'] and sha(dat[new_offset+20:new_offset+20+data_size])==ir_witness_old['dataSha256'],'BINARY_PENDING_INDEX_BINDS_EXACT_BODY')
    require(ir('relocation-read-before-compaction')==ir('relocation-read-after-restart'),'INTERRENAME_NATIVE_GET_PARITY')
    require(ir('compaction-metadata-before')==ir('post-compaction-metadata'),'INTERRENAME_METADATA_PARITY')
    ir_recovery=ir('post-compaction-recovery');ir_roles=ir('post-compaction-before-crash');ir_killed=ir('post-compaction-killed')
    require(set(ir_killed)=={'master','volume','filer','s3'},'INTERRENAME_FOUR_KILLS')
    for role,v in ir_killed.items():require(v['Id']==ir_roles[role]['Id'] and v['State']['ExitCode']==137 and not v['State']['OOMKilled'] and not v['State']['Running'],'INTERRENAME_SIGKILL_BOUND')
    require(mixed_phase['processBefore']['pid']==ir_roles['volume']['State']['Pid'] and ir_roles['volume']['Id'] in mixed_phase['processBefore']['cgroup'],'INTERRENAME_CONTAINER_BINDING')
    ir_exits=ir('interrename-observer-exit')
    require(ir_exits['status']=='ALL_TRACED_THREADS_KILLED' and {str(x['tid']) for x in ir_exits['exits']}==set(mixed_phase['threadStates']) and all(x['signal']==9 for x in ir_exits['exits']),'ALL_MIXED_THREADS_KILLED_WITHOUT_RESUME')
    require(ir('compaction-execution')['vacuumCommands']==1 and ir('compaction-execution')['terminatedBeforeRecovery'] and ir_recovery['additionalVacuumCommands']==ir_recovery['recoveryPutRequests']==ir_recovery['mutatingRetries']==0,'INTERRENAME_NO_MUTATING_REPLAY')
    require(ir_recovery['baselineS3Parity'] and ir_recovery['s3ObjectAbsent'] and ir_recovery['directChunk404'] and ir_recovery['coherentPairAtFirstReadinessBeforeFixtureReads'],'INTERRENAME_BASELINE_ABSENCE_AND_READY_PAIR')
    require(ir('post-compaction-final-read')==summaries['interrename-crash-lab']['object'],'INTERRENAME_S3_SUMMARY_PARITY')
    require(ir_recovery['filerResponseBytesAfter']>ir_recovery['filerResponseBytesBefore'] and ir_recovery['volumeResponseBytesAfter']-ir_recovery['volumeResponseBytesBefore']>=8388865,'INTERRENAME_REAL_RESPONSE_BYTES')
    ir_probes=ir('post-compaction-role-probes');ir_dns=ir('post-compaction-dns-host-probes')
    require(sum(x['allowed'] for x in ir_probes)==11 and len(ir_probes)==32 and len(ir_dns)==15,'INTERRENAME_COMPLETE_MATRIX')
    for x in ir_probes:require(x['connected'] if x['allowed'] else not x['connected'] and x['counterAfter']>x['counterBefore'],'INTERRENAME_ROLE_PROBE')
    require(all(not x['connected'] and x['counterAfter']>x['counterBefore'] for x in ir_dns),'INTERRENAME_DNS_HOST_PROBE')

    # Independently reconstruct both completed renames and the held marker unlink.
    def mo(name):return read('markeronly-crash-lab/'+name+'.json')
    marker_phase=mo('markeronly-freeze');mixed_done=mo('markeronly-recovery')
    require(marker_phase['status']=='OBSERVED_MARKERONLY_FROZEN' and mixed_done['status']=='MARKERONLY_PROCESS_CRASH_RECOVERY_PASS','MARKERONLY_PHASE_AND_RECOVERY')
    require(marker_phase['processBefore']==marker_phase['processFrozen'] and marker_phase['binarySha256']==source_binding['binarySha256'],'MARKERONLY_PROCESS_AND_BINARY')
    require(marker_phase['threadStates'] and set(marker_phase['threadStates'].values())=={'t'} and str(marker_phase['tid']) in marker_phase['threadStates'],'ALL_MIXED_THREADS_STOPPED')
    mo_chunk=mo('cleanup-chunk');mo_target=mo_chunk['datFile'];mo_index=mo_target.removesuffix('.dat')+'.idx'
    stem='/data/'+mo_target.removesuffix('.dat')
    first=marker_phase['beforeDatRenamePhase'];first_files=marker_phase['filesBeforeDatRename']
    before_files=marker_phase['filesBefore'];mixed_files=marker_phase['filesBeforeIdxRename'];marker_files=marker_phase['filesFrozen'];first_exit=marker_phase['firstRenameResult']
    require(first['operation']=='entry' and first['syscallNotResumed'] and first['oldPath']==stem+'.cpd' and first['newPath']==stem+'.dat' and first['number'] in (82,264,316),'EXACT_FIRST_RENAME_ENTRY')
    require(first['threadStates'] and set(first['threadStates'].values())=={'t'},'ALL_THREADS_STOPPED_FOR_FIRST_COPY_CAPTURE')
    require([x['kind'] for x in first['successfulSyncs']]==['marker','directory'] and all(x['returnValue']==0 for x in first['successfulSyncs']),'MARKERONLY_MARKER_DIRECTORY_SYNC')
    require(first_exit['operation']=='exit' and first_exit['returnValue']==0 and not first_exit['isError'] and first_exit['tid']==first['tid'] and first_exit['number']==first['number'] and first_exit['oldPath']==first['oldPath'] and first_exit['newPath']==first['newPath'],'FIRST_RENAME_EXECUTED_SUCCESSFULLY')
    second=marker_phase['beforeIdxRenamePhase'];second_exit=marker_phase['secondRenameResult']
    require(second['operation']=='entry' and second['syscallNotResumed'] and second['number'] in (82,264,316) and second['oldPath']==stem+'.cpx' and second['newPath']==stem+'.idx','EXACT_SECOND_RENAME_ENTRY')
    require(second['threadStates'] and set(second['threadStates'].values())=={'t'},'ALL_THREADS_STOPPED_BEFORE_IDX')
    require(second_exit['operation']=='exit' and second_exit['returnValue']==0 and not second_exit['isError'] and second_exit['tid']==second['tid'] and second_exit['number']==second['number'] and second_exit['oldPath']==second['oldPath'] and second_exit['newPath']==second['newPath'],'SECOND_RENAME_EXECUTED_SUCCESSFULLY')
    require(marker_phase['operation']=='entry' and marker_phase['syscallNotResumed'] and marker_phase['number'] in (87,263) and marker_phase['path']==stem+'.cpc' and str(marker_phase['tid']) in marker_phase['threadStates'],'EXACT_MARKER_UNLINK_ENTRY_NOT_RESUMED')
    post_syncs=marker_phase['postRenameDirectorySyncs']
    require(len(post_syncs)==1 and post_syncs[0]['kind']=='directory' and post_syncs[0]['returnValue']==0,'POST_RENAME_DIRECTORY_SYNC')
    trace=marker_phase['postRenameTrace']
    require([x['kind'] for x in trace]==['idx-rename-exit','directory-fsync-entry','directory-fsync-exit','marker-unlink-entry'],'EXACT_ORDERED_POST_RENAME_TRACE')
    require(trace[0]['tid']==second_exit['tid'] and trace[0]['returnValue']==0 and trace[1]['tid']==trace[2]['tid']==post_syncs[0]['tid'] and trace[2]['returnValue']==0,'ORDERED_RENAME_AND_FSYNC_EXITS')
    require(trace[3]['tid']==marker_phase['tid'] and trace[3]['number']==marker_phase['number'] and trace[3]['path']==marker_phase['path'] and all(str(x['tid']) in marker_phase['threadStates'] for x in trace),'TRACE_BINDS_EXACT_TRACED_PROCESS_AND_MARKER')
    require(set(marker_files)=={'.dat','.idx','.cpc'} and marker_files['.dat']==first_files['.cpd']==mixed_files['.dat'] and marker_files['.idx']==first_files['.cpx']==mixed_files['.cpx'] and marker_files['.cpc']==first_files['.cpc']==mixed_files['.cpc'],'EXACT_COMPLETED_PAIR_AND_ONLY_MARKER')
    require(set(before_files)=={'.dat','.idx'} and set(first_files)=={'.dat','.idx','.cpd','.cpx','.cpc'} and set(mixed_files)=={'.dat','.idx','.cpx','.cpc'},'EXACT_MIXED_FILE_SETS')
    require(all(first_files[ext]==before_files[ext] for ext in before_files),'OLD_PAIR_BEFORE_FIRST_RENAME')
    require(first_files['.cpc']['bytes']==0 and first_files['.cpc']['sha256']==sha(b''),'MARKERONLY_EMPTY_MARKER')
    require(mixed_files['.dat']==first_files['.cpd'] and mixed_files['.dat']!=before_files['.dat'] and mixed_files['.idx']==before_files['.idx'],'NEW_DAT_OLD_IDX_EXACT_INODES')
    require(all(mixed_files[ext]==first_files[ext] for ext in ('.cpx','.cpc')),'PENDING_IDX_AND_MARKER_PRESERVED')
    for prefix,files,extensions in [('markeronly-before-dat-retained',first_files,('.cpd','.cpx','.cpc','.idx')),('markeronly-before-idx-retained',mixed_files,('.dat','.idx','.cpx','.cpc')),('markeronly-frozen-retained',marker_files,('.dat','.idx','.cpc'))]:
        for ext in extensions:
            data=payload['markeronly-crash-lab/'+prefix+ext]
            require(len(data)==files[ext]['bytes'] and sha(data)==files[ext]['sha256'],'RETAINED_MARKERONLY_BYTES')
    require(marker_files==mo('markeronly-stopped-files')==mo('markeronly-gated-files'),'MIXED_FILES_IDENTICAL_UNTIL_EXEC')
    raw_before=marker_phase['rawStorageBefore'];raw_mixed=marker_phase['rawStorageFrozen']
    require(raw_mixed==mo('markeronly-frozen-storage')==mo('markeronly-gated-storage'),'ALL_RAW_FILES_IDENTICAL_UNTIL_EXEC')
    require(set(raw_before)==set(raw_mixed) and raw_before[mo_target]==before_files and raw_mixed[mo_target]==marker_files,'MIXED_RAW_SNAPSHOT_BINDING')
    require(all(raw_before[n]==raw_mixed[n] for n in raw_before if n!=mo_target),'MIXED_UNSELECTED_FILES_IDENTICAL')
    mo_live=mo('markeronly-listeners-ready-files')
    require(set(mo_live)=={'.dat','.idx'} and all(mo_live[ext]==marker_files[ext] for ext in mo_live),'ALREADY_PROMOTED_PAIR_UNCHANGED_AT_FIRST_READINESS')
    require(mo_live==mo('markeronly-recovered-files')==mo('markeronly-final-files'),'RECOVERED_PAIR_PERSISTS')
    mo_old=mo('compaction-before');mo_new=mo('markeronly-listeners-ready-dat')
    require(mo_new==mo('post-compaction-recovered-dat')==mo('post-compaction-final-dat'),'STORAGE_COHERENT_BEFORE_AND_AFTER_FIXTURE_READS')
    require(mo_old['orphanPayloadFiles']==[mo_target] and not mo_new['orphanPayloadFiles'] and not mo_new['temporaryCompactionFiles'] and not mo_new['openDeletedFixtureFiles'],'MARKERONLY_ORPHAN_AND_TEMP_REMOVED')
    require(set(mo_old['datFiles'])==set(mo_new['datFiles']) and set(mo_old['indexes'])==set(mo_new['indexes']),'MARKERONLY_VOLUME_SET_UNCHANGED')
    require(mo_chunk['needleId'] in mo_old['indexes'][mo_index]['deletedNeedles'] and mo_chunk['needleId'] not in mo_new['indexes'][mo_index]['deletedNeedles'] and str(mo_chunk['needleId']) not in mo_new['indexes'][mo_index]['liveNeedles'],'MARKERONLY_ORPHAN_INDEX_REMOVED')
    for name in mo_old['datFiles']:
        idx=name.removesuffix('.dat')+'.idx'
        require(mo_old['indexes'][idx]['liveNeedles']==mo_new['indexes'][idx]['liveNeedles'],'MARKERONLY_ALL_LIVE_NEEDLES')
        require(all(raw_before[name]['.dat'][key]==mo_old['datFiles'][name][key] for key in ('bytes','allocatedBytes','sha256')) and all(raw_before[name]['.idx'][key]==mo_old['indexes'][idx][key] for key in ('bytes','sha256')),'MARKERONLY_BASELINE_BOUND')
        if name!=mo_target:require(mo_old['datFiles'][name]==mo_new['datFiles'][name] and mo_old['indexes'][idx]==mo_new['indexes'][idx],'MARKERONLY_UNSELECTED_VOLUMES_PRESERVED')
    mo_reclaimed=mo_old['datBytes']-mo_new['datBytes'];mo_allocated=mo_old['datAllocatedBytes']-mo_new['datAllocatedBytes']
    require(mo_reclaimed>=4194304 and mo_allocated>=4194304,'MARKERONLY_REAL_SPACE_RECOVERED')
    mo_witness_old=mo('relocation-before-compaction');mo_witness_new=mo('markeronly-listeners-ready-witness')
    require(mo_witness_old==marker_phase['witnessBeforeDatRename'],'WITNESS_EXACT_BEFORE_DAT_RENAME')
    require(mo_witness_new==marker_phase['witnessFrozen']==mo('markeronly-recovered-witness')==mo('relocation-after-restart'),'WITNESS_COHERENT_FROM_FIRST_READINESS')
    for key in ('volumeId','datFile','needleId','cookieHex','fileId','dataBytes','dataSha256','needleSize'):
        require(mo_witness_old[key]==mo_witness_new[key],'MARKERONLY_WITNESS_IDENTITY: '+key)
    require(mo_witness_new['needleOffset']>=8 and mo_witness_new['needleOffset']%8==0 and mo_witness_old['needleOffset']-mo_witness_new['needleOffset']==mo_reclaimed and mo_witness_old['datBytes']-mo_witness_new['datBytes']==mo_reclaimed,'MARKERONLY_WITNESS_RELOCATION')
    # Decode original old IDX and promoted IDX against the retained final DAT.
    import struct
    dat=payload['markeronly-crash-lab/markeronly-frozen-retained.dat']
    def marker_binary_entry(name):
        index=payload['markeronly-crash-lab/'+name]
        require(len(index)%16==0,'COMPLETE_RETAINED_BINARY_INDEX')
        rows=[struct.unpack('>QIi',index[p:p+16]) for p in range(0,len(index),16)]
        found=[(off*8,size) for nid,off,size in rows if nid==mo_witness_old['needleId']]
        require(len(found)==1 and found[0][1]>0,'UNIQUE_RETAINED_WITNESS_INDEX');return found[0]
    old_offset,old_size=marker_binary_entry('markeronly-before-idx-retained.idx');new_offset,new_size=marker_binary_entry('markeronly-frozen-retained.idx')
    require(old_offset==mo_witness_old['needleOffset'] and old_offset>=len(dat) and new_offset==mo_witness_new['needleOffset'] and new_offset>=8 and new_offset%8==0 and old_offset-new_offset==mo_reclaimed and new_offset+20+mo_witness_old['dataBytes']<=len(dat),'RETAINED_OLD_IDX_INVALID_NEW_IDX_VALID')
    cookie,nid,stored_size,data_size=struct.unpack('>IQiI',dat[new_offset:new_offset+20])
    require(nid==mo_witness_old['needleId'] and format(cookie,'08x')==mo_witness_old['cookieHex'] and stored_size==old_size==new_size==mo_witness_new['needleSize'] and data_size==mo_witness_old['dataBytes'] and sha(dat[new_offset+20:new_offset+20+data_size])==mo_witness_old['dataSha256'],'BINARY_PENDING_INDEX_BINDS_EXACT_BODY')
    require(mo('relocation-read-before-compaction')==mo('relocation-read-after-restart'),'MARKERONLY_NATIVE_GET_PARITY')
    require(mo('compaction-metadata-before')==mo('post-compaction-metadata'),'MARKERONLY_METADATA_PARITY')
    mo_recovery=mo('post-compaction-recovery');mo_roles=mo('post-compaction-before-crash');mo_killed=mo('post-compaction-killed')
    require(set(mo_killed)=={'master','volume','filer','s3'},'MARKERONLY_FOUR_KILLS')
    for role,v in mo_killed.items():require(v['Id']==mo_roles[role]['Id'] and v['State']['ExitCode']==137 and not v['State']['OOMKilled'] and not v['State']['Running'],'MARKERONLY_SIGKILL_BOUND')
    require(marker_phase['processBefore']['pid']==mo_roles['volume']['State']['Pid'] and mo_roles['volume']['Id'] in marker_phase['processBefore']['cgroup'],'MARKERONLY_CONTAINER_BINDING')
    mo_exits=mo('markeronly-observer-exit')
    require(mo_exits['status']=='ALL_TRACED_THREADS_KILLED' and {str(x['tid']) for x in mo_exits['exits']}==set(marker_phase['threadStates']) and all(x['signal']==9 for x in mo_exits['exits']),'ALL_MIXED_THREADS_KILLED_WITHOUT_RESUME')
    require(mo('compaction-execution')['vacuumCommands']==1 and mo('compaction-execution')['terminatedBeforeRecovery'] and mo_recovery['additionalVacuumCommands']==mo_recovery['recoveryPutRequests']==mo_recovery['mutatingRetries']==0,'MARKERONLY_NO_MUTATING_REPLAY')
    require(mo_recovery['baselineS3Parity'] and mo_recovery['s3ObjectAbsent'] and mo_recovery['directChunk404'] and mo_recovery['coherentPairAtFirstReadinessBeforeFixtureReads'] and mo_recovery['markerOnlyCrashQualified'] and not mo_recovery['betweenRenamesCrashQualified'],'MARKERONLY_BASELINE_ABSENCE_AND_READY_PAIR')
    require(mo('post-compaction-final-read')==summaries['markeronly-crash-lab']['object'],'MARKERONLY_S3_SUMMARY_PARITY')
    require(mo_recovery['filerResponseBytesAfter']>mo_recovery['filerResponseBytesBefore'] and mo_recovery['volumeResponseBytesAfter']-mo_recovery['volumeResponseBytesBefore']>=8388865,'MARKERONLY_REAL_RESPONSE_BYTES')
    mo_probes=mo('post-compaction-role-probes');mo_dns=mo('post-compaction-dns-host-probes')
    require(sum(x['allowed'] for x in mo_probes)==11 and len(mo_probes)==32 and len(mo_dns)==15,'MARKERONLY_COMPLETE_MATRIX')
    for x in mo_probes:require(x['connected'] if x['allowed'] else not x['connected'] and x['counterAfter']>x['counterBefore'],'MARKERONLY_ROLE_PROBE')
    require(all(not x['connected'] and x['counterAfter']>x['counterBefore'] for x in mo_dns),'MARKERONLY_DNS_HOST_PROBE')

    tests=payload['offline-tests.log'].decode();counts=[int(x) for x in re.findall(r'Ran (\d+) tests? in ',tests)]
    require(sum(counts)==189 and not re.search(r'^FAILED|^OK \(skipped=',tests,re.M),'COMPLETE_189_TEST_REGRESSION')
    return {'schema':'ouf.storage-compaction-markeronly-readback.v1','status':'HOSTED_ORIGINAL_ARCHIVE_READBACK_PASS',
            'producerCommit':producer,'originalZipSha256':sha(raw),'originalZipBytes':len(raw),
            'members':len(payload),'checksumsVerified':len(checks),'sourceBindingsVerified':len(bindings),
            'markerOnlyPhase':marker_phase,'markerOnlyRecovery':mo_recovery,'markerOnlyWitnessBefore':mo_witness_old,'markerOnlyWitnessAfter':mo_witness_new,
            'markerOnlyReclaimedBytes':mo_reclaimed,'markerOnlyReclaimedAllocatedBytes':mo_allocated,'markerOnlyQualified':True,
            'nativeScenarios':len(labs),'testsPassed':sum(counts),'frozenPhase':frozen,'interrenamePhase':mixed_phase,'interrenameRecovery':ir_recovery,
            'interrenameWitnessBefore':ir_witness_old,'interrenameWitnessAfter':ir_witness_new,
            'interrenameReclaimedBytes':ir_reclaimed,'interrenameReclaimedAllocatedBytes':ir_allocated,'postmarkerPhase':phase,'postmarkerWitnessBefore':witness_old,'postmarkerWitnessAfter':witness_new,
            'postmarkerRecovery':pm_recovery,'reclaimedDatBytes':reclaimed,'reclaimedAllocatedBytes':allocated,
            'witness':witness,'recovery':recovery,'sourceBinding':source_binding,
            'cleanFinalStopsReported':sum(r['cleanContainerStops'] for r in summaries.values()),
            'intentionalDeathsReported':sum(r['forcedContainerDeaths'] for r in summaries.values()),
            'distinctContainersReported':sum(r['totalDistinctContainerCount'] for r in summaries.values()),
            'networkRemovedCount':len(labs),'postMarkerQualified':True,'betweenRenamesQualified':True,
            'powerLossQualified':False,'secondNativeExecution':False,'localArchiveReadback':False,
            'targetOperations':0,'gatesClosed':0,'acceptanceTestsPassed':0}

if __name__=='__main__':
    result=verify(Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3],sys.argv[4])
    Path(sys.argv[5]).write_text(json.dumps(result,indent=2)+'\n')
    print('OUF_READBACK_JSON='+json.dumps(result,sort_keys=True))
