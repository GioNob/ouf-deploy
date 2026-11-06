#!/usr/bin/env python3
"""Read the retained post-stop event HOLD. No Docker/systemd/network/write calls.
Event attributes and exec command bodies are never exported.
"""
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

PROGRAM = Path('/var/lib/ouf-storage-host-bound-cold-backup-20261107.py')
PROGRAM_SHA = 'ef76ef3efbbad2caebbfbabbb5c6d40a00fd5cbe09e486cb6ed94e43903af53d'
AREA = Path('/var/lib/ouf-storage-migration/cold-host-bound-20261107-v1')
DECISION = 'GIOVANNI-NONPROD-HOST-BOUND-COLD-20261107-01'
HOST_RESULT_SHA = '35057e4fc3d2becfcb599ee3b7b767ea484f95343ee73768d3964da26cc82592'
SNAPSHOT_SHA = '8c16113535d7435f49c2c876c20141374bdeca103fda55d826a2f8736a46ff88'
SAFE_ACTIONS = {'attach','commit','copy','create','destroy','detach','die','exec_create',
    'exec_start','exec_die','exec_detach','export','health_status','kill','oom','pause',
    'rename','resize','restart','start','stop','top','unpause','update'}


def need(ok, reason):
    if not ok:raise ValueError(reason)


def load_program():
    for parent in reversed(PROGRAM.parents):
        s = parent.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, 'PROGRAM_ANCESTRY')
    fd = os.open(PROGRAM, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        s = os.fstat(stream.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and
             stat.S_IMODE(s.st_mode) == 0o600 and s.st_size == 14686, 'PROGRAM_METADATA')
        raw = stream.read(14687)
    need(hashlib.sha256(raw).hexdigest() == PROGRAM_SHA, 'PROGRAM_DIGEST')
    m = types.ModuleType('pinned_linked_program');m.__file__ = str(PROGRAM)
    exec(compile(raw, str(PROGRAM), 'exec'), m.__dict__)
    return m


class Reader:
    def __init__(self, h):
        self.h, self.hashes, self.bytes, self.until = h, {}, 0, time.monotonic() + 90

    def read(self, relative, allow_empty=False):
        need(time.monotonic() < self.until and len(self.hashes) < 1024, 'LOCAL_REVIEW_BUDGET')
        path = AREA / relative
        if allow_empty:
            parent = self.h['runtime_parent'](path)
            try:
                fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                try:
                    before = os.fstat(fd)
                    need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and
                         stat.S_IMODE(before.st_mode) == 0o600 and 0 <= before.st_size <= 32 << 20, 'PRIVATE_COMMAND_FILE')
                    raw = os.read(fd, (32 << 20) + 1)
                    need(len(raw) == before.st_size and self.h['frame'](before) == self.h['frame'](os.fstat(fd)), 'COMMAND_FILE_CHANGED')
                finally:os.close(fd)
            finally:os.close(parent)
        else:
            raw = self.h['protected'](path, private=True, limit=32 << 20)
        self.bytes += len(raw)
        need(self.bytes <= 192 << 20, 'LOCAL_REVIEW_BYTE_BUDGET')
        self.hashes[relative] = self.h['digest'](raw)
        return raw

    def obj(self, relative):
        return self.h['decode'](self.read(relative))


def action_family(action):
    base = action.split(':', 1)[0]
    return base if base in SAFE_ACTIONS else 'OTHER'


def health_command(doc):
    config = doc.get('Config') or {}
    test = (config.get('Healthcheck') or {}).get('Test') or []
    if not isinstance(test, list) or not test or not all(isinstance(x, str) for x in test):return None
    if test[0] == 'CMD':return ' '.join(test[1:])
    if test[0] == 'CMD-SHELL' and len(test) == 2:
        shell = config.get('Shell') or ['/bin/sh', '-c']
        if isinstance(shell, list) and all(isinstance(x, str) for x in shell):return ' '.join(shell + [test[1]])
    return None


def summarize_events(events, roles, updated, signalled, host):
    expected_health = {cid: health_command(doc) for cid, doc in host.items() if cid in roles}
    exec_matches = {}
    for event in events:
        actor = event.get('Actor') or {};attrs = actor.get('Attributes') or {}
        cid, action = actor.get('ID'), event.get('Action', '')
        need(isinstance(action, str) and isinstance(attrs, dict), 'EVENT_SHAPE')
        if action_family(action) in ('exec_create', 'exec_start') and isinstance(attrs.get('execID'), str):
            suffix = action.partition(':')[2].lstrip(' ') if ':' in action else None
            match = suffix is not None and expected_health.get(cid) is not None and suffix == expected_health[cid]
            exec_matches.setdefault((cid, attrs['execID']), []).append(match)
    counts = collections.Counter();unexpected = 0;unknown_types = 0
    for event in events:
        actor = event.get('Actor') or {};attrs = actor.get('Attributes') or {}
        cid, action = actor.get('ID'), event.get('Action', '')
        family = action_family(action)
        allowed = (cid in updated and action == 'update') or (cid in signalled and
            (action in ('kill','die','stop') or action.startswith('health_status:')))
        unexpected += not allowed
        unknown_types += event.get('Type') != 'container'
        linked = exec_matches.get((cid, attrs.get('execID')), []) if isinstance(attrs.get('execID'), str) else []
        match = all(linked) if linked else None
        role = roles.get(cid)
        category = 'SELECTED_ROLE' if role else 'UPDATED_SHARER' if cid in updated else 'OTHER_CONTAINER'
        exit_code = attrs.get('exitCode')
        exit_code = int(exit_code) if isinstance(exit_code, str) and re.fullmatch(r'-?\d{1,6}', exit_code) else None
        signal = attrs.get('signal')
        signal = signal if isinstance(signal, str) and signal in ('2','9','15','SIGINT','SIGTERM','SIGKILL','INT','TERM','KILL') else None
        counts[(role,category,family,allowed,match,exit_code,signal)] += 1
    rows = [{'role': key[0], 'actorClass': key[1], 'actionFamily': key[2],
        'permittedByOriginalStopFilter': key[3], 'linkedExecCommandMatchesConfiguredHealthcheck': key[4],
        'exitCode': key[5], 'signal': key[6], 'count': count} for key, count in counts.items()]
    return {'eventCount': len(events), 'unexpectedByOriginalFilter': unexpected,
        'nonContainerEventCount': unknown_types, 'atOrAbove256RetainedEvents': len(events) >= 256,
        'groups': rows, 'healthcheckAttributionProven': False, 'eventAuthorizationProven': False,
        'execCommandsOrAttributesExported': False}


def review(h, linked):
    read = Reader(h)
    root_names = linked.directory_names(AREA, 32)
    need({'operation-claim.private.json','plan.private.json','stop','capture','host-checks'} <= root_names, 'LINKED_SCOPE_MEMBERS')
    plan = read.obj('plan.private.json');op = read.obj('operation-claim.private.json')
    need(plan['programSha256'] == PROGRAM_SHA and op['decisionReference'] == DECISION and op['attempts'] == 1, 'LINKED_OPERATION_BINDING')
    link = plan['hostContainmentLink']
    need(link['hostEvidenceSha256'] == op['hostReceiptSha256'] and
         link['hostEvidenceSha256']['continuation-result.json'] == HOST_RESULT_SHA and
         link['runtimeSourceSnapshotSha256'] == SNAPSHOT_SHA, 'HOST_EVIDENCE_BINDING')
    claim = read.obj('stop/claim.private.json');proposal = read.obj('stop/proposal.private.json')
    need(claim['planSha256'] == proposal['planSha256'] == read.hashes['plan.private.json'] and
         claim['decisionReference'] == DECISION and claim['attempts'] == 1, 'STOP_CLAIM_BINDING')
    need(set(plan['roles']) == h['ROLES'] | {'etcd'} and
         proposal['selectedPolicyChanges'] == 13 and proposal['sharingPolicyChanges'] == 22, 'EXACT_STOP_SCOPE')
    need([g['name'] for g in proposal['stopGroups']] ==
         ['ingress','application','identity','data','control'], 'EXACT_GROUP_NAMES')
    names = linked.directory_names(AREA / 'stop', 1024)
    numbers = sorted(int(m.group(1)) for n in names if (m := re.fullmatch(r'command-(\d{3})\.private', n)))
    need(numbers and numbers == list(range(4, numbers[-1] + 1)) and numbers[-1] <= 256, 'CONTIGUOUS_CHARGED_COMMANDS')
    last = numbers[-1]
    need(last >= 7, 'FINAL_INVENTORY_SEQUENCE_REQUIRED')
    command_raws = {};nonempty_stderr = 0
    for n in numbers:
        command_raws[n] = read.read('stop/command-%03d.private' % n, allow_empty=True)
        stderr = read.read('stop/command-%03d.stderr.private' % n, allow_empty=True)
        nonempty_stderr += bool(stderr)
    expected_actions = [('RESTART_NO', row['containerId'], ['update','--restart=no',row['containerId']]) for row in proposal['policyChanges']]
    expected_actions += [('STOP_SIGNAL', row['containerId'], ['kill',row['proposedArgv'][-2],row['containerId']]) for group in proposal['stopGroups'] for row in group['signals']]
    need(len(expected_actions) == 49, 'EXACT_49_ACTIONS')
    allowed_names = {'claim.private.json','proposal.private.json','docker-client'}
    allowed_names |= {'command-%03d%s.private' % (n, suffix) for n in numbers for suffix in ('','.stderr')}
    verified = 0
    output_hashes = {h['digest'](raw) for raw in command_raws.values()}
    for ordinal, (kind, cid, args) in enumerate(expected_actions, 1):
        stem = 'action-%03d' % ordinal
        intent = read.obj('stop/' + stem + '.intent.private.json')
        reply = read.obj('stop/' + stem + '.reply.private.json')
        need(intent['kind'] == kind and intent['containerId'] == cid and intent['args'] == args and
             intent['state'] == 'INTENT_BEFORE_CALL' and intent['automaticRetryAllowed'] is False, 'ACTION_SCOPE_MISMATCH')
        need(reply['commandReturnedSuccess'] is True and reply['responseSha256'] in output_hashes, 'ACTION_REPLY_BINDING')
        allowed_names |= {stem + '.intent.private.json',stem + '.reply.private.json'}
        if kind == 'RESTART_NO':
            need(read.obj('stop/' + stem + '.verified.private.json')['postconditionVerified'] is True, 'POLICY_POSTCONDITION_RECEIPT')
            allowed_names.add(stem + '.verified.private.json');verified += 1
    groups = []
    for group in proposal['stopGroups']:
        name = group['name'] + '.stopped.private.json';item = read.obj('stop/' + name)
        need(set(item['containerIds']) == {x['containerId'] for x in group['signals']} and item['physicalStopVerified'] is True, 'GROUP_STOP_RECEIPT')
        allowed_names.add(name);groups.append(group['name'])
    need(names == allowed_names, 'STOP_SCOPE_UNEXPECTED_ENTRY_OR_RESULT')
    need(linked.directory_names(AREA / 'stop/docker-client', 0) == set(), 'DOCKER_CLIENT_NOT_EMPTY')
    selected = h['decode'](command_raws[last - 2])
    others = [h['decode'](line) for line in command_raws[last - 1].splitlines()]
    ids = command_raws[last - 3].decode().split()
    docs = selected + others;host = {x['Id']: x for x in docs}
    need(len(ids) == len(set(ids)) == len(host) == len(docs) == 145 and set(ids) == set(host), 'RETAINED_FINAL_HOST_INVENTORY')
    roles = {row['containerId']: role for role,row in plan['roles'].items()}
    need({x['Id'] for x in selected} == set(roles), 'SELECTED_FINAL_INVENTORY')
    role_states = {}
    for cid, role in roles.items():
        doc = host[cid];state = doc['State'];row = plan['roles'][role]
        need(type(state.get('ExitCode')) is int, 'INTEGER_EXIT_CODE_REQUIRED')
        need(h['fingerprint'](doc) == row['fingerprint'], 'ROLE_GENERATION_CHANGED')
        clean = (not state.get('Running') and state.get('Status') == 'exited' and state.get('Pid') == 0 and
            state.get('ExitCode') in ((0,) if role in ('postgres','minio','etcd') else (0,143)) and
            not state.get('OOMKilled') and not state.get('Error') and not state.get('Paused') and not state.get('Restarting'))
        role_states[role] = {'cleanExitAtRetainedObservation': clean, 'exitCode': state.get('ExitCode'),
            'restartPolicyNo': doc['HostConfig']['RestartPolicy']['Name'] == 'no'}
    sharing = h['shared_outside_bindings'](host, set(roles), plan['sources'])
    sharing_matches = sharing == plan['stoppedSharingContainers']
    sharing_restart_no = all(host[cid]['HostConfig']['RestartPolicy']['Name'] == 'no' for cid in sharing)
    events = [h['decode'](line) for line in command_raws[last].splitlines()]
    need(events and all(isinstance(e, dict) for e in events), 'RETAINED_EVENT_STREAM_REQUIRED')
    updated = {row['containerId'] for row in proposal['policyChanges']}
    event_summary = summarize_events(events, roles, updated, set(roles), host)
    capture_entries = linked.directory_names(AREA / 'capture', 1024)
    host_entries = linked.directory_names(AREA / 'host-checks', 1024)
    # Verify bytes still match after the grouped read. No provider queries or live source reads.
    for relative, sha in list(read.hashes.items()):
        need(h['digest'](read.read(relative, allow_empty=relative.startswith('stop/command-'))) == sha, 'LOCAL_RECEIPT_CHANGED_DURING_READ')
    return {'schema': 'ouf.storage-cold-event-held-readback.v1', 'status': 'RETAINED_POST_STOP_EVENT_REVIEW',
        'planSha256': read.hashes['plan.private.json'], 'operationClaimSha256': read.hashes['operation-claim.private.json'],
        'eventStreamSha256': read.hashes['stop/command-%03d.private' % last], 'eventCommandOrdinal': last,
        'nonemptyCommandStderrFiles': nonempty_stderr,
        'retainedJournalDigest': h['digest'](h['canonical'](read.hashes)), 'filesBound': len(read.hashes),
        'mutationIntentsBound': len(expected_actions), 'mutationRepliesBound': len(expected_actions),
        'verifiedRestartPolicyReceipts': verified, 'stoppedGroups': groups, 'retainedRoles': role_states,
        'retainedHostContainerCount': len(host), 'retainedRunningContainerCount': sum(bool(x['State'].get('Running')) for x in host.values()),
        'retainedSharingMatchesPlan': sharing_matches, 'retainedSharingRestartNo': sharing_restart_no,
        'events': event_summary, 'captureDirectoryEmpty': not capture_entries,
        'captureEntryCount': len(capture_entries), 'hostCheckEntryCount': len(host_entries),
        'stopSuccessResultPresent': 'result.json' in names, 'topSuccessResultPresent': 'result.json' in root_names,
        'currentLiveStateProven': False, 'credentialBearingMetadataReadLocally': True,
        'credentialOrConfigurationBodiesExported': False, 'sourceBodiesRead': 0,
        'filesWritten': 0, 'providerRequests': 0, 'automaticReplayAllowed': False,
        'automaticRestartAllowed': False, 'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}


if __name__ == '__main__':
    try:
        need(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode, 'ROOT_ISOLATED_REQUIRED')
        linked = load_program();d = linked.pinned(linked.STOP, linked.STOP_SHA)
        h, _ = d.bootstrap()
        print(json.dumps(review(h, linked), sort_keys=True))
    except Exception as error:
        print(json.dumps({'status': 'HELD', 'reason': str(error) if type(error).__name__ in ('ValueError','Held') else type(error).__name__,
            'filesWritten': 0, 'providerRequests': 0, 'automaticReplayAllowed': False,
            'automaticRestartAllowed': False, 'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}))
        sys.exit(2)
