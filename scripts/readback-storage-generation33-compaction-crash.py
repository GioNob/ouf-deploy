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
          'compaction-lab','compaction-restart-lab','relocation-lab','compaction-crash-lab']
    summaries={name:read(name+'/receipt.json') for name in labs}
    for name,r in summaries.items():
        require(r['status']=='SYNTHETIC_ROLE_NETWORK_ISOLATION_PASS','NATIVE_SCENARIO_PASS: '+name)
        require(r['networkRemoved'] and r['retainedNamespacePinsReleased'] and r['cleanContainerStops']==5,'NATIVE_CLEANUP: '+name)
        require(r['targetOperations']==r['gatesClosed']==r['acceptanceTestsPassed']==r['mutatingRequestRetries']==0,'UNCHANGED_AUTHORITY_AND_RETRIES')
    stopped=[read(name) for name in payload if name.endswith('-stopped.json')]
    require(len(stopped)==55 and all(not x['Running'] and x['ExitCode']==0 and not x['OOMKilled'] for x in stopped),'ALL_55_CLEAN_FINAL_STOPS')
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
    tests=payload['offline-tests.log'].decode();counts=[int(x) for x in re.findall(r'Ran (\d+) tests? in ',tests)]
    require(sum(counts)==146 and not re.search(r'^FAILED',tests,re.M),'COMPLETE_146_TEST_REGRESSION')
    return {'schema':'ouf.storage-compaction-precommit-readback.v1','status':'HOSTED_ORIGINAL_ARCHIVE_READBACK_PASS',
            'producerCommit':producer,'originalZipSha256':sha(raw),'originalZipBytes':len(raw),
            'members':len(payload),'checksumsVerified':len(checks),'sourceBindingsVerified':len(bindings),
            'nativeScenarios':len(labs),'testsPassed':sum(counts),'frozenPhase':frozen,
            'witness':witness,'recovery':recovery,'sourceBinding':source_binding,
            'cleanFinalStopsReported':sum(r['cleanContainerStops'] for r in summaries.values()),
            'intentionalDeathsReported':sum(r['forcedContainerDeaths'] for r in summaries.values()),
            'distinctContainersReported':sum(r['totalDistinctContainerCount'] for r in summaries.values()),
            'networkRemovedCount':len(labs),'postMarkerQualified':False,'betweenRenamesQualified':False,
            'powerLossQualified':False,'secondNativeExecution':False,'localArchiveReadback':False,
            'targetOperations':0,'gatesClosed':0,'acceptanceTestsPassed':0}

if __name__=='__main__':
    result=verify(Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3],sys.argv[4])
    Path(sys.argv[5]).write_text(json.dumps(result,indent=2)+'\n')
    print('OUF_READBACK_JSON='+json.dumps(result,sort_keys=True))
