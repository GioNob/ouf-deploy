#!/usr/bin/env python3
"""Project the exact prepared plan and retained policies; no Engine requests."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time

PROGRAM = Path('/var/lib/ouf-storage-cold-backup-v3.py')
PROGRAM_SHA = 'b23a822d0fd7000ac8806d47ff66c0ab053f0fa60ce33998268af792b9db53ac'
PLAN_SHA = '1c0bb62ceba85f748e43465d36f016b4c575c586d40390dc92095a1dbc71bd0f'


def project(plan, host, helper, now):
    need = helper['need']
    ids = {r['containerId'] for r in plan['roles'].values()}
    need(len(ids) == 14 and set(plan['roles']) == helper['ROLES'] | {'etcd'}, 'EXACT_ROSTER')
    need(len(plan['sources']) == 34 and len(plan['runtimeSources']) == 5, 'EXACT_SOURCE_COUNTS')
    sharing = helper['shared_outside_bindings'](host, ids, plan['sources'])
    need(sharing == plan['stoppedSharingContainers'] and len(sharing) == 103, 'EXACT_SHARING_BINDINGS')
    policies = ('no', 'always', 'unless-stopped', 'on-failure')
    counts = {p: 0 for p in policies}
    roles = {}
    for role, row in sorted(plan['roles'].items()):
        doc = host[row['containerId']]
        need(helper['fingerprint'](doc) == row['fingerprint'], 'ROLE_GENERATION_CHANGED')
        need(doc['State']['Running'] == row['wasRunning'], 'ROLE_STATE_CHANGED')
        need(doc['HostConfig']['RestartPolicy'] == row['originalRestartPolicy'], 'ROLE_POLICY_CHANGED')
        name = row['originalRestartPolicy']['Name']
        need(name in policies, 'UNKNOWN_ROLE_POLICY')
        roles[role] = {'runningAtPreparation': row['wasRunning'], 'restartPolicyAtPreparation': name,
                       'restartPolicyChangeRequiredByCapture': name != 'no'}
    for cid in sharing:
        name = host[cid]['HostConfig']['RestartPolicy']['Name']
        need(name in policies, 'UNKNOWN_SHARING_POLICY')
        counts[name] += 1
    return {'schema': 'ouf.storage-cold-plan-impact.v1', 'status': 'PREPARED_PLAN_IMPACT_READ',
        'planSha256': PLAN_SHA, 'createdEpoch': plan['createdEpoch'], 'validUntilEpoch': plan['validUntilEpoch'],
        'planUnexpiredAtRead': now <= plan['validUntilEpoch'], 'roles': roles,
        'sharingContainerPoliciesAtPreparation': counts,
        'sharingContainerPolicyChangesRequiredByCapture': 103 - counts['no'],
        'sharedContainersToStart': 0, 'sourceCount': 34, 'reviewedRuntimeSources': 5,
        'runtimeEntriesBound': sum(r['entryCount'] for r in plan['runtimeSources'].values()),
        'runtimeFileBytesBound': sum(r['fileBytes'] for r in plan['runtimeSources'].values()),
        'includesWholeSharedPostgresCluster': plan['includesWholeSharedPostgresCluster'],
        'maximumCaptureSeconds': plan['maximumSeconds'], 'maximumProducedBytes': plan['maximumProducedBytes'],
        'currentLiveContainerStateProven': False, 'externalContainmentProven': False,
        'sourceBodiesRead': 0, 'providerRequests': 0, 'filesModified': 0,
        'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}


def main():
    if not (os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
        raise ValueError('ROOT_ISOLATED_PYTHON')
    fd = os.open(PROGRAM, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not (stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_size == 32524
                and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o600):
            raise ValueError('PROGRAM_METADATA')
        raw = os.read(fd, 32525)
    finally:
        os.close(fd)
    if hashlib.sha256(raw).hexdigest() != PROGRAM_SHA:
        raise ValueError('PROGRAM_DIGEST')
    h = {'__name__': 'plan_readback_only', '__file__': str(PROGRAM)}
    exec(compile(raw, str(PROGRAM), 'exec'), h)
    need, read, decode = h['need'], h['protected'], h['decode']
    need(h['digest'](read(PROGRAM, private=True)) == PROGRAM_SHA, 'PROGRAM_CHANGED')
    area = h['AREA']
    names = ('plan.private.json', 'command-001.private', 'command-002.private', 'command-003.private')
    raws = {name: read(area / name, private=True) for name in names}
    need(h['digest'](raws['plan.private.json']) == PLAN_SHA, 'EXACT_PREPARED_PLAN_REQUIRED')
    plan = decode(raws['plan.private.json'])
    need(plan['programSha256'] == PROGRAM_SHA, 'PLAN_PROGRAM_BINDING')
    docs = decode(raws['command-002.private']) + [decode(line) for line in raws['command-003.private'].splitlines()]
    ids = raws['command-001.private'].decode().split()
    need(0 < len(ids) <= 192 and len(ids) == len(set(ids)) == len(docs)
         and {d['Id'] for d in docs} == set(ids), 'INVENTORY_COMPLETENESS')
    result = project(plan, {d['Id']: d for d in docs}, h, int(time.time()))
    result['ageAtExpectedPathPresent'] = Path('/usr/bin/age').is_file()
    result['localAvailableBytesNow'] = shutil.disk_usage(area).free
    result['localInputSha256'] = {name: h['digest'](raw) for name, raw in raws.items()}
    for name, raw in raws.items():
        need(read(area / name, private=True) == raw, 'RETAINED_INPUT_CHANGED')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'status': 'HELD', 'reason': 'PLAN_IMPACT_BINDING_CHECK_FAILED',
                          'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False,
                          'acceptanceCreditAdded': 0}))
        sys.exit(1)
