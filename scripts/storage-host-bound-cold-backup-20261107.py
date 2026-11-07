#!/usr/bin/env python3
"""One separately approved Docker stop/capture linked to successful host containment.
Preserves old attempts, original expiry and cumulative Docker read consumption.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import types

AREA = Path('/var/lib/ouf-storage-migration/cold-host-bound-20261107-v1')
HOST_AREA = Path('/var/lib/ouf-storage-host-continuation-20261106-v1')
HOST_SNAPSHOT_SHA = '8c16113535d7435f49c2c876c20141374bdeca103fda55d826a2f8736a46ff88'
HOST_RESULT_SHA = '35057e4fc3d2becfcb599ee3b7b767ea484f95343ee73768d3964da26cc82592'
HOST_CORE = Path('/var/lib/ouf-storage-host-containment-fixed-20261106.py')
HOST_CORE_SHA = '05f4e5166a4818d6d6b5a33651e4d4d39888245b2ebe0a3d1ae07a9c28a148ec'
STOP = Path('/var/lib/ouf-storage-test-cold-stop-20261106.py')
STOP_SHA = 'b3b28645ed377459fbe577fe4eb5eb8fb351a0e2c0e3f7067d5745f6f83ad2b5'
OLD_STOP_PINS = {'claim.private.json': '786b60aa3d5217b73120a277218d73d3e5edd138bc26b8ed1f66a8d741215ee9',
    'proposal.private.json': '62b2afd01e215f0da5719c3e22cda1d1c19d11747bc80e102d611b8af5ff5df5'}
OLD_DECISION = 'GIOVANNI-NONPROD-COLD-20261106-01'
DECISION = 'GIOVANNI-NONPROD-HOST-BOUND-COLD-20261107-01'
EXPECTED_HOST = 145
EXPECTED_POLICY = (13, 22)


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def pinned(path, digest):
    for parent in reversed(path.parents):
        s = parent.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, 'PROGRAM_ANCESTRY')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        s = os.fstat(stream.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and
             stat.S_IMODE(s.st_mode) == 0o600 and 0 < s.st_size < 65536, 'PROGRAM_METADATA')
        raw = stream.read(65536)
    need(hashlib.sha256(raw).hexdigest() == digest, 'PROGRAM_DIGEST')
    m = types.ModuleType('pinned_' + path.stem);m.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), m.__dict__)
    return m


def directory_names(path, maximum):
    s = path.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o700, 'PRIVATE_DIRECTORY')
    names = set()
    with os.scandir(path) as entries:
        for entry in entries:
            names.add(entry.name)
            need(len(names) <= maximum, 'DIRECTORY_ENTRY_LIMIT')
    return names


def private_receipt(h, path):
    if not path.name.endswith('.stderr.private'):
        return h['protected'](path, private=True)
    parent = h['runtime_parent'](path)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and
                 stat.S_IMODE(before.st_mode) == 0o600 and before.st_size == 0, 'EMPTY_PRIVATE_STDERR_REQUIRED')
            need(os.read(fd, 1) == b'' and h['frame'](before) == h['frame'](os.fstat(fd)), 'STDERR_CHANGED')
            return b''
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def old_stop_review(h, d, p, plan, retained):
    expected = {'claim.private.json', 'proposal.private.json', 'docker-client'}
    expected |= {'command-%03d%s.private' % (n, suffix) for n in range(1, 4) for suffix in ('', '.stderr')}
    need(directory_names(d.AREA, len(expected)) == expected, 'OLD_STOP_HAS_MUTATION_OR_OTHER_ENTRY')
    need(directory_names(d.AREA / 'docker-client', 0) == set(), 'OLD_DOCKER_CLIENT_NOT_EMPTY')
    raws = {n: private_receipt(h, d.AREA / n) for n in sorted(expected - {'docker-client'})}
    hashes = {n: h['digest'](raw) for n, raw in raws.items()}
    need(all(hashes[n] == sha for n, sha in OLD_STOP_PINS.items()), 'OLD_STOP_PIN_CHANGED')
    claim = h['decode'](raws['claim.private.json'])
    need(claim['planSha256'] == h['digest'](h['canonical'](plan)) and claim['attempts'] == 1 and
         claim['decisionReference'] == OLD_DECISION and claim['maximumSeconds'] == 1200 and
         claim['maximumCommandCalls'] == 256 and claim['maximumMetadataBytes'] == 64 << 20, 'OLD_STOP_CLAIM')
    proposal = p['compile_proposal'](plan, retained, h, claim['planSha256'], plan['createdEpoch'], test_preservation=True)
    need(raws['proposal.private.json'] == h['canonical'](proposal), 'OLD_STOP_PROPOSAL')
    ids = raws['command-001.private'].decode().split()
    docs = h['decode'](raws['command-002.private']) + [h['decode'](x) for x in raws['command-003.private'].splitlines()]
    need(len(ids) == len(set(ids)) == len(docs) == EXPECTED_HOST and {x['Id'] for x in docs} == set(ids), 'OLD_READ_INVENTORY')
    need(all(raws['command-%03d.stderr.private' % n] == b'' for n in range(1, 4)), 'OLD_READ_STDERR_REQUIRES_REVIEW')
    d.check_host(h, plan, retained, {x['Id']: x for x in docs}, set(), set(), set())
    byte_count = sum(len(raw) for n, raw in raws.items() if n.startswith('command-'))
    need(byte_count < 64 << 20, 'OLD_STOP_BYTE_BUDGET')
    return hashes, byte_count


def host_review(h):
    names = ('continuation-result.json', 'runtime-snapshot.private.json', 'reviewed-draft.private.json',
             'preflight.private.json', 'final-units.private.json', 'claim.private.json')
    raws = {n: h['protected'](HOST_AREA / n, private=True) for n in names}
    hashes = {n: h['digest'](raw) for n, raw in raws.items()}
    need(hashes['continuation-result.json'] == HOST_RESULT_SHA and
         hashes['runtime-snapshot.private.json'] == HOST_SNAPSHOT_SHA, 'EXACT_SUCCESSFUL_HOST_RECEIPT')
    result = h['decode'](raws['continuation-result.json'])
    need(result['status'] == 'HOST_WRITERS_CONTAINED_NEW_STOP_PLAN_REQUIRED' and
         result['overrideFilesWritten'] == 6 and result['timersDisabledAndStopped'] == 5 and
         result['registryDisabledAndStopped'] is True and result['priorAttemptPreserved'] is True and
         result['forcedServiceKills'] == 0, 'HOST_SUCCESS_REQUIRED')
    draft = h['decode'](raws['reviewed-draft.private.json'])
    need(hashes['reviewed-draft.private.json'] == result['draftSha256'], 'HOST_DRAFT_BINDING')
    preflight = h['decode'](raws['preflight.private.json'])
    return {'result': result, 'snapshot': h['decode'](raws['runtime-snapshot.private.json']),
        'draft': draft, 'cgroups': preflight['unitCgroups'], 'hashes': hashes,
        'evidence': {n: h['decode'](raw) for n, raw in raws.items()}}


def bind_plan(h, old_plan, host_context, program_sha):
    snapshot = host_context['snapshot']
    need(set(snapshot) == set(old_plan['runtimeSources']) and len(snapshot) == 5, 'EXACT_FIVE_RUNTIME_PATHS')
    need(host_context['result']['legacyValidUntilEpoch'] == old_plan['validUntilEpoch'], 'LEGACY_EXPIRY_BINDING')
    need(snapshot != old_plan['runtimeSources'], 'EXPECTED_PRIOR_RUNTIME_DRIFT')
    plan = copy.deepcopy(old_plan)
    plan['runtimeSources'] = copy.deepcopy(snapshot)
    plan['programSha256'] = program_sha
    plan['hostContainmentLink'] = {'schema': 'ouf.storage-host-bound-plan-link.v1',
        'derivedFromPlanSha256': h['digest'](h['canonical'](old_plan)),
        'hostEvidenceSha256': host_context['hashes'], 'runtimeSourceSnapshotSha256': HOST_SNAPSHOT_SHA,
        'hostRecoveryEvidence': copy.deepcopy(host_context['evidence']),
        'offlineOverrideText': '[Service]\nRestart=no\nSendSIGKILL=no\nRuntimeDirectoryPreserve=yes\nTimeoutStopSec=120s\n',
        'hostRestoreRequiresSeparateGovernedAction': True,
        'change': 'FIVE_RUNTIME_IDENTITIES_AFTER_VERIFIED_HOST_CONTAINMENT_ONLY',
        'expiryRenewed': False, 'oldAttemptReused': False, 'runtimeAuthorityIssued': False}
    return plan


def host_check(h, core, p, context, runner):
    core.verify_files(h, context['draft'])
    for service in tuple(p.SERVICES) + (p.REGISTRY,):
        path = core.SYSTEMD_ROOT / (service + '.d') / core.OVERRIDE_NAME
        need(h['protected'](path, private=True, limit=4096) == core.OVERRIDE, 'HOST_OVERRIDE_CHANGED')
    runner.cgroups = dict(context['cgroups'])
    rows = core.wait_inactive(p, runner, tuple(p.TIMERS) + tuple(p.SERVICES) + (p.REGISTRY,), timeout=0)
    core.check_units(p, rows, context['draft'], patched=True)
    need(all(p.one(rows[n], 'UnitFileState') == 'disabled' for n in tuple(p.TIMERS) + (p.REGISTRY,)), 'HOST_WRITER_REENABLED')
    need(all(h['digest'](h['protected'](HOST_AREA / n, private=True)) == sha for n, sha in context['hashes'].items()), 'HOST_RECEIPT_CHANGED')


def execute(h, d, planner, core, p, old_plan, retained, context, public, decision, program_sha):
    need(decision == DECISION, 'EXACT_LINKED_STOP_CAPTURE_DECISION')
    need(not os.path.lexists(AREA), 'LINKED_OPERATION_ALREADY_CLAIMED')
    need(time.time() + 4800 <= old_plan['validUntilEpoch'], 'ORIGINAL_PLAN_WINDOW_INSUFFICIENT')
    old_hashes, old_bytes = old_stop_review(h, d, planner, old_plan, retained)
    plan = bind_plan(h, old_plan, context, program_sha)
    proposal = planner['compile_proposal'](plan, retained, h, h['digest'](h['canonical'](plan)), int(time.time()), test_preservation=True)
    need((proposal['selectedPolicyChanges'], proposal['sharingPolicyChanges']) == EXPECTED_POLICY, 'EXACT_POLICY_SCOPE')
    fd = h['runtime_parent'](AREA);os.close(fd)
    AREA.mkdir(mode=0o700)
    h['new'](AREA / 'operation-claim.private.json', h['canonical']({
        'schema': 'ouf.storage-host-bound-cold-claim.v1', 'decisionReference': decision,
        'oldStopReceiptSha256': old_hashes, 'hostReceiptSha256': context['hashes'],
        'priorStopReadCalls': 3, 'priorStopReadBytes': old_bytes, 'oldStopTimeAllowanceChargedSeconds': 1200,
        'separateStopSeconds': 1200, 'maximumCumulativeStopAllowanceSeconds': 2400,
        'maximumCumulativeStopCliCalls': 256, 'maximumCumulativeStopMetadataBytes': 64 << 20,
        'captureSeconds': 3600, 'captureMaximumProducedBytes': 64 << 30,
        'attempts': 1, 'legacyValidUntilEpoch': plan['validUntilEpoch'],
        'automaticReplayAllowed': False, 'automaticRestartAllowed': False, 'runtimeAuthorityIssued': False}))
    h['new'](AREA / 'plan.private.json', h['canonical'](plan))
    for name in ('host-checks', 'stop', 'capture'):
        (AREA / name).mkdir(mode=0o700)
    guard = core.Runner(h, AREA / 'host-checks')
    guard.until = time.monotonic() + 4800  # Read-only guard shares whole operation window.
    host_check(h, core, p, context, guard)
    h['verify_runtime_sources'](plan)
    stop_run = d.bounded_runner(h, AREA / 'stop')
    stop_run.calls, stop_run.total = 3, old_bytes
    stop_result = d.stop_once(h, planner, plan, retained, AREA / 'stop', stop_run, decision)
    host_check(h, core, p, context, guard)
    h['verify_runtime_sources'](plan)
    capture_run = h['Runner'](AREA / 'capture', seconds=3600)
    capture_result = h['capture'](plan, h['digest'](h['canonical'](plan)), AREA / 'capture', capture_run, public, decision)
    host_check(h, core, p, context, guard)
    h['verify_runtime_sources'](plan)
    need(time.time() <= plan['validUntilEpoch'] and time.monotonic() < guard.until, 'LINKED_OPERATION_TIME_LIMIT')
    need(all(h['digest'](private_receipt(h, d.AREA / name)) == sha for name, sha in old_hashes.items()), 'OLD_STOP_JOURNAL_CHANGED')
    result = dict(capture_result, schema='ouf.storage-host-bound-cold-result.v1',
        hostContainmentVerifiedBeforeStopBeforeAndAfterCapture=True, hostReadOnlyChecks=guard.calls,
        oldStopAttemptPreserved=True, priorStopReadCalls=3, priorStopReadBytes=old_bytes,
        cumulativeStopCommandCalls=stop_run.calls, cumulativeStopMetadataBytes=stop_run.total,
        policyChanges=stop_result['policyChanges'], selectedRolesStopped=stop_result['selectedRolesStopped'],
        forcedContainerKills=0, legacyExpiryExtended=False, runtimeAuthorityIssued=False)
    h['new'](AREA / 'result.json', h['canonical'](result))
    return result


def main():
    need(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode, 'ROOT_ISOLATED_REQUIRED')
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--decision-reference', required=True)
    parser.add_argument('--exclusive-operator-maintenance', action='store_true', required=True)
    parser.add_argument('--nonproduction-test-state', action='store_true', required=True)
    args = parser.parse_args()
    d, core = pinned(STOP, STOP_SHA), pinned(HOST_CORE, HOST_CORE_SHA)
    h, planner = d.bootstrap()
    p, _ = core.bootstrap()
    raw = h['protected'](d.LEGACY_AREA / 'plan.private.json', private=True)
    need(h['digest'](raw) == d.PLAN_SHA, 'EXACT_LEGACY_PLAN')
    legacy = h['decode'](raw)
    inputs = {n: h['protected'](d.LEGACY_AREA / n, private=True) for n in d.RETAINED}
    need(all(h['digest'](inputs[n]) == sha for n, sha in d.RETAINED.items()), 'RETAINED_INVENTORY_DIGEST')
    docs = h['decode'](inputs['command-002.private']) + [h['decode'](x) for x in inputs['command-003.private'].splitlines()]
    retained = {x['Id']: x for x in docs}
    need(len(retained) == len(docs) == EXPECTED_HOST and set(inputs['command-001.private'].decode().split()) == set(retained), 'RETAINED_HOST_MEMBERSHIP')
    plan = h['derive_legacy_plan'](legacy, retained, d.WRAPPER_SHA)
    need(h['protected'](h['AREA'] / 'plan.private.json', private=True) == h['canonical'](plan), 'ORIGINAL_DERIVED_PLAN_CHANGED')
    need(not os.path.lexists(d.LEGACY_AREA / 'capture') and not os.path.lexists(h['AREA'] / 'capture'), 'ORIGINAL_CAPTURE_ALREADY_ATTEMPTED')
    context = host_review(h)
    recipient = h['protected'](Path('/var/lib/ouf-storage-cipher-preparation-20261106/recipient.pub'), private=True)
    need(h['digest'](recipient) == d.RECIPIENT_SHA, 'RECIPIENT_CHANGED')
    need(h['digest'](h['protected'](Path('/usr/bin/age'), limit=64 << 20)) == d.AGE_SHA, 'AGE_BINARY_CHANGED')
    self_raw = h['protected'](Path(__file__), private=True, limit=65536)
    print(json.dumps(execute(h, d, planner, core, p, plan, retained, context,
        h['recipient'](recipient), args.decision_reference, h['digest'](self_raw)), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'HELD', 'reason': str(error) if type(error).__name__ in ('ValueError', 'Held', 'PropertyIssue') else type(error).__name__,
            'partialOperationPreserved': True, 'automaticReplayAllowed': False,
            'automaticRestartAllowed': False, 'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}))
        sys.exit(2)
