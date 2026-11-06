#!/usr/bin/env python3
"""One-shot operator maintenance stop for initial NONPRODUCTION preservation.

Never reopens traffic, grants runtime authority, retries mutations or force-kills
containers. Applicable external approval and exclusive maintenance remain needed.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

PROGRAM = Path('/var/lib/ouf-storage-cold-backup-v3.py')
PROGRAM_SHA = 'b23a822d0fd7000ac8806d47ff66c0ab053f0fa60ce33998268af792b9db53ac'
PLANNER = Path('/var/lib/ouf-storage-stop-planner-20261106.py')
PLANNER_SHA = '121f998eabb7f09b00d6e2cc22bbeaa49c78cec3b535f02c46e57e6eb9c71e68'
PLAN_SHA = '1c0bb62ceba85f748e43465d36f016b4c575c586d40390dc92095a1dbc71bd0f'
RECIPIENT_SHA = '20582d7f592199d5964fc64ece8d035bdf3b93df026c5e222eca615c0f8bb2c0'
AGE_SHA = 'eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c'
AREA = Path('/var/lib/ouf-storage-migration/cold-test-stop-20261106-v1')
MAX_COMMANDS = 256
MAX_METADATA = 64 << 20
RETAINED = {
    'command-001.private': 'feb9b30580486678ba5c86dd0af9f31d7bbf957f6606b38f819c04e7b31097c1',
    'command-002.private': '44dc112c351eea66ec85243826222f0c8c020f8f055b41b75c7b91ea8dc8d725',
    'command-003.private': '542579b873133e4600c89a4909e42e336ec1beb74b6ec20158245f8c317e1560',
}


def bootstrap():
    for path in [Path('/'), Path('/var'), Path('/var/lib')]:
        s = path.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError('PROTECTED_PROGRAM_ANCESTRY')
    fd = os.open(PROGRAM, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        if not (stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and
                stat.S_IMODE(s.st_mode) == 0o600 and s.st_size == 32524):
            raise ValueError('PINNED_PROGRAM_METADATA')
        raw = f.read(32525)
    if hashlib.sha256(raw).hexdigest() != PROGRAM_SHA:
        raise ValueError('PINNED_PROGRAM_DIGEST')
    h = {'__name__': 'backup_definitions_only', '__file__': str(PROGRAM)}
    exec(compile(raw, str(PROGRAM), 'exec'), h)
    planner = h['protected'](PLANNER, private=True)
    h['need'](h['digest'](planner) == PLANNER_SHA, 'PLANNER_DIGEST')
    p = {'__name__': 'proposal_definitions_only'}
    exec(compile(planner, str(PLANNER), 'exec'), p)
    return h, p


def check_host(h, plan, retained, current, updated, signalled, completed):
    need = h['need']
    need(set(current) == set(retained), 'HOST_MEMBERSHIP_CHANGED')
    ids = {r['containerId'] for r in plan['roles'].values()}
    need(h['shared_outside_bindings'](current, ids, plan['sources']) ==
         plan['stoppedSharingContainers'], 'SHARED_GENERATION_CHANGED')
    roles = {r['containerId']: (role, r) for role, r in plan['roles'].items()}
    for cid, d in current.items():
        state = d['State']
        need(not state.get('Paused') and not state.get('Restarting'), 'PAUSED_OR_RESTARTING')
        policy = d['HostConfig']['RestartPolicy']
        expected = retained[cid]['HostConfig']['RestartPolicy']
        need(policy == ({'Name': 'no', 'MaximumRetryCount': 0} if cid in updated else expected),
             'UNEXPECTED_RESTART_POLICY')
        if cid in roles:
            role, row = roles[cid]
            need(h['fingerprint'](d) == row['fingerprint'], 'ROLE_GENERATION_CHANGED')
            if cid not in signalled:
                need(state.get('Running') and state.get('Pid', 0) > 0, 'UNEXPECTED_EARLY_STOP')
            if cid in completed or not state.get('Running'):
                allowed = (0,) if role in ('postgres', 'minio', 'etcd') else (0, 143)
                need(state.get('Status') == 'exited' and state.get('Pid') == 0 and
                     state.get('ExitCode') in allowed and not state.get('OOMKilled') and
                     not state.get('Error'), 'UNCLEAN_STOP')
        else:
            need(not state.get('Running') and state.get('Pid') == 0, 'UNBOUND_ACTIVE_PROCESS')
            need(d['Mounts'] == retained[cid]['Mounts'] and state == retained[cid]['State'],
                 'OUTSIDE_CONTAINER_CHANGED')


def bounded_runner(h, root):
    class BoundedRunner(h['Runner']):
        def run(self, argv, output=None, cap=32 << 20, timeout=120):
            h['need'](self.calls < MAX_COMMANDS and self.total < MAX_METADATA,
                      'STOP_COMMAND_OR_BYTE_BUDGET')
            # Both stdout and stderr have this RLIMIT; their sum stays bounded.
            cap = min(cap, (MAX_METADATA - self.total) // 2)
            h['need'](cap > 0, 'STOP_METADATA_BUDGET')
            return super().run(argv, output=output, cap=cap, timeout=timeout)
    return BoundedRunner(root, seconds=1200)


def stop_once(h, p, plan, retained, root, run, decision_reference,
              wall=time.time, monotonic=time.monotonic, sleep=time.sleep):
    """Root is exclusively created by caller; claim and intents survive interruption."""
    need, new, canonical = h['need'], h['new'], h['canonical']
    need(re.fullmatch('[A-Za-z0-9_.:-]{1,128}', decision_reference), 'DECISION_REFERENCE_REQUIRED')
    need(wall() + 1200 + plan['maximumSeconds'] <= plan['validUntilEpoch'], 'PLAN_WINDOW_TOO_SHORT')
    proposal = p['compile_proposal'](plan, retained, h, h['digest'](canonical(plan)), int(wall()),
                                     test_preservation=True)
    new(root / 'claim.private.json', canonical({
        'schema': 'ouf.storage-test-cold-stop-claim.v1', 'planSha256': h['digest'](canonical(plan)),
        'decisionReference': decision_reference, 'profile': proposal['profile'], 'attempts': 1,
        'maximumSeconds': 1200, 'maximumCommandCalls': MAX_COMMANDS, 'maximumMetadataBytes': MAX_METADATA,
        'authorityAuthenticatedByUtility': False, 'externalContainmentAuthenticated': False,
        'automaticReplayAllowed': False}))
    new(root / 'proposal.private.json', canonical(proposal))
    ids = {r['containerId'] for r in plan['roles'].values()}
    updated, signalled, completed = set(), set(), set()
    until = monotonic() + 1200
    event_start = str(wall())

    def check_budget():
        need(monotonic() < until and wall() <= plan['validUntilEpoch'], 'STOP_TIME_BUDGET')
        need(run.calls < MAX_COMMANDS and run.total <= MAX_METADATA, 'STOP_COMMAND_OR_BYTE_BUDGET')

    def inventory():
        check_budget()
        result = run.inventory(ids)
        check_budget()
        check_host(h, plan, retained, result, updated, signalled, completed)
        return result

    journal = [0]

    def action_target(cid):
        check_budget()
        docs = h['decode'](run.docker('inspect', cid, timeout=15, cap=8 << 20))
        need(len(docs) == 1 and docs[0].get('Id') == cid, 'ACTION_TARGET_ID')
        doc = docs[0]
        expected = {'Name': 'no', 'MaximumRetryCount': 0} if cid in updated else retained[cid]['HostConfig']['RestartPolicy']
        need(doc['HostConfig']['RestartPolicy'] == expected, 'ACTION_POLICY_CHANGED')
        role_rows = {row['containerId']: row for row in plan['roles'].values()}
        if cid in role_rows:
            need(h['fingerprint'](doc) == role_rows[cid]['fingerprint'], 'ACTION_GENERATION_CHANGED')
            state = doc['State']
            need(state.get('Running') and state.get('Pid', 0) > 0 and
                 not state.get('Paused') and not state.get('Restarting'), 'ACTION_TARGET_NOT_RUNNING')
        else:
            need(h['shared_outside_bindings']({cid: doc}, ids, plan['sources']) ==
                 {cid: plan['stoppedSharingContainers'][cid]}, 'ACTION_SHARING_CHANGED')
        return doc

    def mutation(kind, cid, args):
        check_budget()
        action_target(cid)
        journal[0] += 1
        stem = root / ('action-%03d' % journal[0])
        new(Path(str(stem) + '.intent.private.json'), canonical({
            'kind': kind, 'containerId': cid, 'args': args,
            'automaticRetryAllowed': False, 'state': 'INTENT_BEFORE_CALL'}))
        # Timeout/lost response propagates: never advance or resend the command.
        result = run.docker(*args, timeout=15, cap=1 << 20)
        new(Path(str(stem) + '.reply.private.json'), canonical({
            'commandReturnedSuccess': True, 'responseSha256': h['digest'](result),
            'postconditionVerified': False}))

    inventory()
    h['verify_runtime_sources'](plan)
    for row in proposal['policyChanges']:
        mutation('RESTART_NO', row['containerId'], ['update', '--restart=no', row['containerId']])
        updated.add(row['containerId'])
        action_target(row['containerId'])
        new(root / ('action-%03d.verified.private.json' % journal[0]), canonical({'postconditionVerified': True}))
    inventory()  # All policy postconditions before any stop signal.
    for group in proposal['stopGroups']:
        inventory()  # Detect drift or a premature stop before sending this group.
        for row in group['signals']:
            cid = row['containerId']
            signal = row['proposedArgv'][-2]
            mutation('STOP_SIGNAL', cid, ['kill', signal, cid])
            signalled.add(cid)
        group_ids = {r['containerId'] for r in group['signals']}
        deadline = monotonic() + group['maximumWaitSeconds']
        while True:
            check_budget()
            docs = h['decode'](run.docker('inspect', *sorted(group_ids), timeout=15, cap=8 << 20))
            need(len(docs) == len(group_ids) and {d['Id'] for d in docs} == group_ids, 'GROUP_INSPECT_MEMBERSHIP')
            if all(not d['State'].get('Running') for d in docs):
                break
            need(monotonic() < deadline, 'GROUP_STOP_TIMEOUT_NO_FORCE')
            sleep(5)
        completed.update(group_ids)
        inventory()
        new(root / (group['name'] + '.stopped.private.json'), canonical({'containerIds': sorted(group_ids),
            'physicalStopVerified': True, 'applicationDrainProven': False}))
    current = inventory()
    h['offline'](plan, current)
    check_budget()
    events = [h['decode'](line) for line in run.docker('events', '--since', event_start,
        '--until', str(int(wall()) + 1), '--filter', 'type=container', '--format', '{{json .}}',
        timeout=15, cap=4 << 20).splitlines()]
    for event in events:
        cid, action = (event.get('Actor') or {}).get('ID'), event.get('Action', '')
        permitted = (cid in updated and action == 'update') or (
            cid in signalled and (action in ('kill', 'die', 'stop') or action.startswith('health_status:')))
        need(permitted, 'UNEXPECTED_CONTAINER_EVENT')
    check_budget()
    result = {'schema': 'ouf.storage-test-cold-stop-result.v1', 'status': 'STOPPED_OFFLINE_CAPTURE_PENDING',
        'planSha256': h['digest'](canonical(plan)), 'policyChanges': len(updated),
        'selectedRolesStopped': len(completed), 'mutationCalls': journal[0], 'commandCalls': run.calls,
        'metadataBytes': run.total, 'remainingRunningContainers': 0, 'sharedContainersStarted': 0,
        'automaticReplayAllowed': False, 'automaticRestartAllowed': False,
        'applicationDrainProven': False, 'applicationConsistencyProven': False,
        'ambiguousApplicationWorkPreservedForReconciliation': True,
        'externalContainmentAuthenticated': False, 'runtimeAuthorityIssued': False,
        'targetCapturePerformed': False, 'acceptanceCreditAdded': 0}
    new(root / 'result.json', canonical(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--decision-reference', required=True)
    parser.add_argument('--exclusive-operator-maintenance', action='store_true', required=True)
    parser.add_argument('--nonproduction-test-state', action='store_true', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if not (os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
        raise ValueError('ROOT_ISOLATED_PYTHON_REQUIRED')
    h, p = bootstrap()
    read, need = h['protected'], h['need']
    raw = read(h['AREA'] / 'plan.private.json', private=True)
    need(h['digest'](raw) == PLAN_SHA, 'EXACT_PLAN_DIGEST')
    plan = h['decode'](raw)
    need(plan['programSha256'] == PROGRAM_SHA, 'PLAN_PROGRAM_DIGEST')
    need(time.time() + 4800 <= plan['validUntilEpoch'], 'PLAN_WINDOW_TOO_SHORT')
    inputs = {name: read(h['AREA'] / name, private=True) for name in RETAINED}
    need(all(h['digest'](inputs[n]) == v for n, v in RETAINED.items()), 'RETAINED_INVENTORY_DIGEST')
    docs = h['decode'](inputs['command-002.private']) + [h['decode'](x) for x in inputs['command-003.private'].splitlines()]
    ids = inputs['command-001.private'].decode().split()
    need(len(ids) == len(set(ids)) == len(docs) == 145 and {d['Id'] for d in docs} == set(ids), 'EXACT_HOST_INVENTORY')
    host = {d['Id']: d for d in docs}
    proposal = p['compile_proposal'](plan, host, h, PLAN_SHA, int(time.time()), test_preservation=True)
    need(proposal['selectedPolicyChanges'] == 13 and proposal['sharingPolicyChanges'] == 22, 'EXACT_35_POLICIES')
    recipient = read(Path('/var/lib/ouf-storage-cipher-preparation-20261106/recipient.pub'), private=True)
    need(h['digest'](recipient) == RECIPIENT_SHA, 'RECIPIENT_DIGEST')
    need(h['digest'](read(Path('/usr/bin/age'), limit=64 << 20)) == AGE_SHA, 'AGE_DIGEST')
    need(not os.path.lexists(h['AREA'] / 'capture'), 'CAPTURE_ALREADY_ATTEMPTED')
    for ancestor in [AREA.parent, *AREA.parent.parents]:
        s = ancestor.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, 'PROTECTED_OPERATION_AREA')
    # Exclusive directory is the permanent single-attempt fence, even before claim.
    AREA.mkdir(mode=0o700)
    run = bounded_runner(h, AREA)
    print(json.dumps(stop_once(h, p, plan, host, AREA, run, args.decision_reference), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        reason = str(error) if type(error).__name__ in ('Held', 'ValueError') else type(error).__name__
        print(json.dumps({'status': 'HELD', 'reason': reason, 'partialOperationPreserved': True,
            'automaticReplayAllowed': False, 'automaticRestartAllowed': False,
            'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}))
        sys.exit(2)
