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
    for path,digest in bindings.items():require(sha((source/path).read_bytes())==digest,'EXACT_SOURCE: '+path)
    def read(path):return json.loads(payload[path])
    labs=['lab','crash-lab','filer-crash-lab','master-crash-lab','all-crash-lab','stream-lab','cleanup-lab',
          'compaction-lab','compaction-restart-lab','relocation-lab','compaction-crash-lab','commit-crash-lab']
    summaries={name:read(name+'/receipt.json') for name in labs}
    for name,r in summaries.items():
        require(r['status']=='SYNTHETIC_ROLE_NETWORK_ISOLATION_PASS','NATIVE_SCENARIO_PASS: '+name)
        require(r['networkRemoved'] and r['retainedNamespacePinsReleased'] and r['cleanContainerStops']==5,'NATIVE_CLEANUP: '+name)
        require(r['targetOperations']==r['gatesClosed']==r['acceptanceTestsPassed']==r['mutatingRequestRetries']==0,'UNCHANGED_AUTHORITY_AND_RETRIES')
    stopped=[read(name) for name in payload if name.endswith('-stopped.json')]
    require(len(stopped)==60 and all(not x['Running'] and x['ExitCode']==0 and not x['OOMKilled'] for x in stopped),'ALL_60_CLEAN_FINAL_STOPS')
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
    require(witness_new['needleOffset']==8 and witness_old['needleOffset']-witness_new['needleOffset']==reclaimed and witness_old['datBytes']-witness_new['datBytes']==reclaimed,'WITNESS_REAL_RELOCATION')
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

    tests=payload['offline-tests.log'].decode();counts=[int(x) for x in re.findall(r'Ran (\d+) tests? in ',tests)]
    require(sum(counts)==157 and not re.search(r'^FAILED|^OK \(skipped=',tests,re.M),'COMPLETE_157_TEST_REGRESSION')
    return {'schema':'ouf.storage-compaction-postmarker-readback.v1','status':'HOSTED_ORIGINAL_ARCHIVE_READBACK_PASS',
            'producerCommit':producer,'originalZipSha256':sha(raw),'originalZipBytes':len(raw),
            'members':len(payload),'checksumsVerified':len(checks),'sourceBindingsVerified':len(bindings),
            'nativeScenarios':len(labs),'testsPassed':sum(counts),'frozenPhase':frozen,'postmarkerPhase':phase,'postmarkerWitnessBefore':witness_old,'postmarkerWitnessAfter':witness_new,
            'postmarkerRecovery':pm_recovery,'reclaimedDatBytes':reclaimed,'reclaimedAllocatedBytes':allocated,
            'witness':witness,'recovery':recovery,'sourceBinding':source_binding,
            'cleanFinalStopsReported':sum(r['cleanContainerStops'] for r in summaries.values()),
            'intentionalDeathsReported':sum(r['forcedContainerDeaths'] for r in summaries.values()),
            'distinctContainersReported':sum(r['totalDistinctContainerCount'] for r in summaries.values()),
            'networkRemovedCount':len(labs),'postMarkerQualified':True,'betweenRenamesQualified':False,
            'powerLossQualified':False,'secondNativeExecution':False,'localArchiveReadback':False,
            'targetOperations':0,'gatesClosed':0,'acceptanceTestsPassed':0}

if __name__=='__main__':
    result=verify(Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3],sys.argv[4])
    Path(sys.argv[5]).write_text(json.dumps(result,indent=2)+'\n')
    print('OUF_READBACK_JSON='+json.dumps(result,sort_keys=True))
