#!/usr/bin/env python3
"""Read retained stop journal and compare five runtime sources locally.
No Docker/provider calls, writes, plan refresh, replay or runtime authority.
Runtime file bodies may contain credentials: hash locally, export no bodies/names.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

DRIVER = Path('/var/lib/ouf-storage-test-cold-stop-20261106.py')
DRIVER_SHA = 'b3b28645ed377459fbe577fe4eb5eb8fb351a0e2c0e3f7067d5745f6f83ad2b5'
FIELDS = ('device', 'inode', 'mode', 'uid', 'gid', 'links', 'bytes', 'mtime_ns', 'ctime_ns')


def compare_identity(old, current):
    before = {row['path']: row for row in old['entries']}
    after = {row['path']: row for row in current['entries']}
    changed = []
    for index, key in enumerate(sorted(set(before) | set(after))):
        a, b = before.get(key), after.get(key)
        if a == b:
            continue
        changed.append({'entryOrdinal': index,
            'presence': 'ADDED' if a is None else 'REMOVED' if b is None else 'BOTH',
            'changedFrameFields': [field for i, field in enumerate(FIELDS) if a and b and a['frame'][i] != b['frame'][i]],
            'bodyHashEqual': a.get('sha256') == b.get('sha256') if a and b and 'sha256' in a and 'sha256' in b else None,
            'xattrsEqual': a['xattrs'] == b['xattrs'] if a and b else None})
    return {'identityEqual': old == current, 'entriesBefore': old['entryCount'],
        'entriesNow': current['entryCount'], 'fileBytesBefore': old['fileBytes'],
        'fileBytesNow': current['fileBytes'], 'changedEntries': changed,
        'entryNamesExported': False, 'bodiesExported': False, 'xattrValuesExported': False}


def journal_summary(names, group_names):
    intents = [n for n in names if re.fullmatch(r'action-[0-9]{3}\.intent\.private\.json', n)]
    replies = [n for n in names if re.fullmatch(r'action-[0-9]{3}\.reply\.private\.json', n)]
    verified = [n for n in names if re.fullmatch(r'action-[0-9]{3}\.verified\.private\.json', n)]
    commands = [n for n in names if re.fullmatch(r'command-[0-9]{3}\.private', n)]
    groups = [g for g in group_names if g + '.stopped.private.json' in names]
    allowed = {'claim.private.json', 'proposal.private.json', 'docker-client', 'result.json'}
    allowed |= set(intents + replies + verified + commands)
    allowed |= {n for n in names if re.fullmatch(r'command-[0-9]{3}\.stderr\.private', n)}
    allowed |= {g + '.stopped.private.json' for g in group_names}
    unknown = len(set(names) - allowed)
    pre = not intents and not replies and not verified and not groups and set(commands) == {
        'command-001.private', 'command-002.private', 'command-003.private'} and not unknown and 'result.json' not in names
    return {'intentReceipts': len(intents), 'replyReceipts': len(replies),
        'verifiedPolicyReceipts': len(verified), 'commandOutputFiles': len(commands),
        'stoppedGroupReceipts': groups, 'unknownScopeEntries': unknown,
        'successResultPresent': 'result.json' in names,
        'consistentWithPreMutationSourceHold': pre,
        'phaseInference': 'PRE_MUTATION_SOURCE_REVIEW' if pre else
            'FINAL_SOURCE_REVIEW_POSSIBLE' if len(intents) == 49 and len(groups) == 5 else 'REQUIRES_REVIEW',
        'currentLiveContainerStateProven': False}


def main():
    if not (os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
        raise ValueError('ROOT_ISOLATED_PYTHON_REQUIRED')
    for p in (Path('/'), Path('/var'), Path('/var/lib')):
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError('PROGRAM_ANCESTRY')
    fd = os.open(DRIVER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        if not (stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600 and s.st_size == 15186):
            raise ValueError('DRIVER_METADATA')
        raw = f.read(15187)
    if hashlib.sha256(raw).hexdigest() != DRIVER_SHA:
        raise ValueError('DRIVER_DIGEST')
    d = {'__name__': 'definitions_only', '__file__': str(DRIVER)}
    exec(compile(raw, str(DRIVER), 'exec'), d)
    h, p = d['bootstrap']()  # Definitions only: no Runner, inventory or mutation.
    read, need, decode = h['protected'], h['need'], h['decode']
    old_raw = read(d['LEGACY_AREA'] / 'plan.private.json', private=True)
    need(h['digest'](old_raw) == d['PLAN_SHA'], 'LEGACY_PLAN_DIGEST')
    old = decode(old_raw)
    inputs = {n: read(d['LEGACY_AREA'] / n, private=True) for n in d['RETAINED']}
    need(all(h['digest'](inputs[n]) == sha for n, sha in d['RETAINED'].items()), 'RETAINED_INPUT_DIGEST')
    docs = decode(inputs['command-002.private']) + [decode(line) for line in inputs['command-003.private'].splitlines()]
    host = {x['Id']: x for x in docs}
    need(len(host) == len(docs) == 145 and set(inputs['command-001.private'].decode().split()) == set(host), 'RETAINED_HOST_MEMBERSHIP')
    expected = h['derive_legacy_plan'](old, host, d['WRAPPER_SHA'])
    plan_raw = read(h['AREA'] / 'plan.private.json', private=True)
    need(plan_raw == h['canonical'](expected), 'DERIVED_PLAN_CHANGED')
    plan = decode(plan_raw)
    root = d['AREA']
    claim_raw = read(root / 'claim.private.json', private=True)
    claim = decode(claim_raw)
    need(claim['planSha256'] == h['digest'](plan_raw) and claim['attempts'] == 1 and
         claim['decisionReference'] == 'GIOVANNI-NONPROD-COLD-20261106-01', 'CLAIM_BINDING')
    proposal_raw = read(root / 'proposal.private.json', private=True)
    proposal = p['compile_proposal'](plan, host, h, h['digest'](plan_raw), plan['createdEpoch'], test_preservation=True)
    need(proposal_raw == h['canonical'](proposal), 'PROPOSAL_CHANGED')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(before.st_uid == 0 and stat.S_IMODE(before.st_mode) == 0o700, 'PRIVATE_SCOPE_DIRECTORY')
        names = []
        with os.scandir(fd) as iterator:
            for entry in iterator:
                names.append(entry.name)
                need(len(names) <= 1024, 'SCOPE_ENTRY_LIMIT')
        need(h['frame'](before) == h['frame'](os.fstat(fd)), 'SCOPE_CHANGED_DURING_LIST')
    finally:
        os.close(fd)
    journal = journal_summary(names, [g['name'] for g in proposal['stopGroups']])
    need(not journal['unknownScopeEntries'], 'UNKNOWN_SCOPE_MEMBER')
    need(len(plan['runtimeSources']) == 5, 'EXACT_FIVE_RUNTIME_SOURCES')
    comparisons = []
    until = time.monotonic() + 90
    for source, identity in sorted(plan['runtimeSources'].items()):
        need(time.monotonic() < until, 'REVIEW_TIME_BUDGET')
        source_sha = h['digest'](source.encode())
        roles = sorted(role for role, hashes in h['REVIEWED_RUN_BINDINGS'].items() if source_sha in hashes)
        need(bool(roles), 'SOURCE_NOT_IN_REVIEWED_BINDINGS')
        result = {'sourcePathSha256': source_sha, 'roles': roles}
        try:
            h['source_path'](source)
            result.update(compare_identity(identity, h['runtime_source_identity'](source)))
            result['status'] = 'CURRENT_LOCAL_IDENTITY_COMPARED'
        except h['Held'] as error:
            result.update(status='HELD', reason=str(error))
        except OSError as error:
            result.update(status='UNAVAILABLE', reason=type(error).__name__, errno=error.errno)
        comparisons.append(result)
    print(json.dumps({'schema': 'ouf.storage-cold-runtime-drift-readback.v1',
        'status': 'LOCAL_HELD_JOURNAL_AND_RUNTIME_COMPARISON', 'journal': journal,
        'legacyPlanSha256': h['digest'](old_raw), 'derivedPlanSha256': h['digest'](plan_raw),
        'claimSha256': h['digest'](claim_raw), 'proposalSha256': h['digest'](proposal_raw),
        'captureDirectoryPresent': os.path.lexists(h['AREA'] / 'capture'),
        'runtimeComparisons': comparisons, 'comparisonIsCurrentNotSnapshotAtFailure': True,
        'credentialBearingBodiesMayBeReadLocally': True, 'bodiesExported': False,
        'providerRequests': 0, 'filesWritten': 0, 'scopeConsumed': True,
        'automaticReplayAllowed': False, 'automaticRestartAllowed': False,
        'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}, sort_keys=True))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        reason = str(error) if type(error).__name__ in ('Held', 'ValueError') else type(error).__name__
        print(json.dumps({'status': 'HELD', 'reason': reason, 'providerRequests': 0,
            'filesWritten': 0, 'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False,
            'acceptanceCreditAdded': 0}))
        sys.exit(2)
