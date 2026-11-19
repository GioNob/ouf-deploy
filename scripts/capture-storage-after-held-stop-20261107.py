#!/usr/bin/env python3
"""Explicit capture-only continuation of a sealed nonproduction stop.
Never retries the stop, attributes the three etcd execs, or reopens any service.
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

READER = Path('/var/lib/ouf-storage-cold-event-reader-20261107.py')
READER_SHA = '3d96e397c3331c4ab17c32a517338f56135c7d9c9120e236be2295af30ff794a'
REPORT_SHA = '917b75fa209a4d85aadd92a42913d45eb8f53869c9e2cf1e878f3a1c4b51ddd1'
PLAN_SHA = 'f4cc75450360a1a30a7210b5ee8e492bc99c6737d98131537b87b65fa284cc3d'
JOURNAL_SHA = '5f3416a62555adf1d6b4dc00370bd72cf33c0844bb7d671aaae05c08f4bc741f'
AREA = Path('/var/lib/ouf-storage-migration/capture-after-held-stop-20261107-v1')
DECISION = 'GIOVANNI-NONPROD-CAPTURE-ONLY-20261107-01'


def need(ok, reason):
    if not ok:raise ValueError(reason)


def pinned(path, sha):
    for parent in reversed(path.parents):
        s = parent.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, 'PROGRAM_ANCESTRY')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        s = os.fstat(stream.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and
             stat.S_IMODE(s.st_mode) == 0o600 and 0 < s.st_size < 65536, 'PROGRAM_METADATA')
        raw = stream.read(65536)
    need(hashlib.sha256(raw).hexdigest() == sha, 'PROGRAM_DIGEST')
    m = types.ModuleType('pinned_' + path.stem);m.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), m.__dict__)
    return m


def sealed_stop(h, reader, linked, core, p):
    report = reader.review(h, linked)
    need(h['digest'](h['canonical'](report)) == REPORT_SHA, 'EXACT_OPERATOR_READBACK_REQUIRED')
    need(report['captureDirectoryEmpty'] and not report['stopSuccessResultPresent'] and
         not report['topSuccessResultPresent'] and report['retainedRunningContainerCount'] == 0 and
         report['retainedSharingMatchesPlan'] and report['retainedSharingRestartNo'] and
         all(x['cleanExitAtRetainedObservation'] and x['restartPolicyNo'] for x in report['retainedRoles'].values()), 'SEALED_OFFLINE_EFFECTS_REQUIRED')
    need(linked.directory_names(reader.AREA, 8) ==
         {'operation-claim.private.json','plan.private.json','stop','capture','host-checks'}, 'EXACT_OLD_OPERATION_MEMBERS')
    read = reader.Reader(h)
    names = ['plan.private.json', 'operation-claim.private.json'] + [
        'stop/' + n for n in sorted(linked.directory_names(reader.AREA / 'stop', 1024)) if n != 'docker-client']
    final = report['eventCommandOrdinal']
    evidence = {}
    # Retain all digest bindings, and the final inventory/events plus action receipts
    # themselves INSIDE the encrypted backup. Never print private evidence.
    for name in names:
        raw = read.read(name, allow_empty=name.startswith('stop/command-'))
        if not name.startswith('stop/command-') or name in {
                'stop/command-%03d.private' % n for n in range(final - 3, final + 1)}:
            evidence[name] = raw.decode('utf-8')
    need(h['digest'](h['canonical'](read.hashes)) == JOURNAL_SHA == report['retainedJournalDigest'], 'SEALED_JOURNAL_CHANGED')
    raw_plan = evidence.pop('plan.private.json')
    need(h['digest'](raw_plan.encode()) == PLAN_SHA == report['planSha256'], 'EXACT_STOP_PLAN_REQUIRED')
    plan = h['decode'](raw_plan)
    host_path = reader.AREA / 'host-checks'
    need(linked.directory_names(host_path, 2) == {'command-001.private.json'}, 'ONE_PRIOR_HOST_READ_REQUIRED')
    host_raw = h['protected'](host_path / 'command-001.private.json', private=True)
    host = h['decode'](host_raw)
    props = tuple(dict.fromkeys(p.PROPS + core.EXTRA + ('Slice',)))
    expected = ['show', '--all', *sorted(p.EXPECTED), *['--property=' + k for k in props]]
    need(host['binary'] == 'systemctl' and host['args'] == expected and host['returncode'] == 0, 'PRIOR_HOST_SHOW_BINDING')
    prior_bytes = len(host['stdout'].encode()) + len(host['stderr'].encode())
    return {'report': report, 'plan': plan, 'journalHashes': read.hashes,
        'privateEvidence': evidence, 'priorHostReceipt': host,
        'priorHostReceiptSha256': h['digest'](host_raw), 'priorHostBytes': prior_bytes}


def capture_runner(h, root, deadline):
    class ReadOnlyCaptureRunner(h['Runner']):
        def docker(self, *args, **kw):
            need(args and (args[0] in ('ps','inspect','export','events') or
                 args[:2] in (('network','inspect'), ('image','save'))), 'CAPTURE_DOCKER_READ_ONLY')
            return super().docker(*args, **kw)
    run = ReadOnlyCaptureRunner(root, seconds=3600)
    run.until = deadline
    return run


def execute(h, reader, linked, core, p, context, public, decision, program_sha):
    need(decision == DECISION, 'EXACT_CAPTURE_CONTINUATION_DECISION')
    need(not os.path.lexists(AREA), 'CAPTURE_CONTINUATION_ALREADY_CLAIMED')
    deadline = time.monotonic() + 3600
    sealed = sealed_stop(h, reader, linked, core, p)
    original = sealed['plan']
    need(time.time() + 3600 <= original['validUntilEpoch'], 'ORIGINAL_CAPTURE_WINDOW_INSUFFICIENT')
    need(original['hostContainmentLink']['hostEvidenceSha256'] == context['hashes'] and
         original['runtimeSources'] == context['snapshot'], 'HOST_AND_RUNTIME_LINK_CHANGED')
    need(original['maximumSeconds'] == 3600 and original['maximumProducedBytes'] == 64 << 30, 'ORIGINAL_CAPTURE_BUDGET_REQUIRED')
    # This is archival of a held test state, not retroactive approval of etcd execs.
    plan = copy.deepcopy(original)
    plan['programSha256'] = program_sha
    plan['captureAfterHeldStop'] = {'schema': 'ouf.storage-capture-after-held-stop-context.v1',
        'decisionReference': decision, 'originalPlanSha256': PLAN_SHA,
        'retainedJournalDigest': JOURNAL_SHA, 'retainedReadback': sealed['report'],
        'journalHashes': sealed['journalHashes'], 'privateStopEvidence': sealed['privateEvidence'],
        'priorHostReceipt': sealed['priorHostReceipt'], 'priorHostReceiptSha256': sealed['priorHostReceiptSha256'],
        'unattributedEtcdExecSequences': 3, 'eventAuthorizationProven': False,
        'previousStopResultChanged': False, 'applicationConsistencyProven': False,
        'intendedUse': 'OFFLINE_NONPRODUCTION_TEST_STATE_PRESERVATION',
        'expiryExtended': False, 'stopReplayed': False, 'captureAttemptPreviouslyStarted': False}
    fd = h['runtime_parent'](AREA);os.close(fd)
    AREA.mkdir(mode=0o700)
    h['new'](AREA / 'claim.private.json', h['canonical']({
        'schema': 'ouf.storage-capture-after-held-stop-claim.v1', 'decisionReference': decision,
        'originalPlanSha256': PLAN_SHA, 'planSha256': h['digest'](h['canonical'](plan)),
        'retainedJournalDigest': JOURNAL_SHA, 'attempts': 1, 'previousCaptureAttempts': 0,
        'priorCumulativeStopCommandCalls': sealed['report']['eventCommandOrdinal'],
        'priorCumulativeStopTimeAllowanceChargedSeconds': 2400, 'newStopAllowanceSeconds': 0,
        'captureSeconds': 3600, 'maximumProducedBytes': 64 << 30, 'maximumCaptureCommands': 256,
        'priorHostReadCallsCharged': 1, 'priorHostReadBytesCharged': sealed['priorHostBytes'],
        'legacyValidUntilEpoch': plan['validUntilEpoch'], 'automaticReplayAllowed': False,
        'automaticRestartAllowed': False, 'authorityAuthenticatedByThisUtility': False}))
    h['new'](AREA / 'plan.private.json', h['canonical'](plan))
    for name in ('host-checks','capture'):(AREA / name).mkdir(mode=0o700)
    class ReadOnlyHostRunner(core.Runner):
        def run(self, binary, args, mutation=False):
            need(not mutation, 'HOST_MUTATION_FORBIDDEN')
            return super().run(binary, args, mutation=False)
    guard = ReadOnlyHostRunner(h, AREA / 'host-checks')
    guard.until, guard.calls, guard.bytes = deadline, 1, sealed['priorHostBytes']
    linked.host_check(h, core, p, context, guard)
    h['verify_runtime_sources'](plan)
    run = capture_runner(h, AREA / 'capture', deadline)
    result = h['capture'](plan, h['digest'](h['canonical'](plan)), AREA / 'capture', run, public, decision)
    linked.host_check(h, core, p, context, guard)
    h['verify_runtime_sources'](plan)
    after = sealed_stop(h, reader, linked, core, p)
    need(after == sealed, 'PRIOR_OPERATION_CHANGED_DURING_CAPTURE')
    need(time.monotonic() < deadline and time.time() <= plan['validUntilEpoch'], 'CAPTURE_CONTINUATION_TIME_LIMIT')
    result = dict(result, schema='ouf.storage-capture-after-held-stop-result.v1',
        priorStopJournalPreserved=True, priorStopSuccessFabricated=False,
        priorCumulativeStopCommandCalls=sealed['report']['eventCommandOrdinal'],
        stopSignalsSent=0, restartPoliciesChanged=0, hostMutations=guard.mutations,
        cumulativeHostReadCalls=guard.calls, priorHostReadCallsCharged=1,
        unattributedEtcdExecSequencesPreserved=3, eventAuthorizationProven=False,
        legacyExpiryExtended=False, priorCaptureAttemptReplayed=False, runtimeAuthorityIssued=False)
    h['new'](AREA / 'result.json', h['canonical'](result))
    return result


def main():
    need(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode, 'ROOT_ISOLATED_REQUIRED')
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--decision-reference', required=True)
    parser.add_argument('--exclusive-operator-maintenance', action='store_true', required=True)
    parser.add_argument('--preserve-held-nonproduction-state-with-unattributed-etcd-execs', action='store_true', required=True)
    args = parser.parse_args()
    reader = pinned(READER, READER_SHA)
    linked = reader.load_program()
    d, core = linked.pinned(linked.STOP, linked.STOP_SHA), linked.pinned(linked.HOST_CORE, linked.HOST_CORE_SHA)
    h, _ = d.bootstrap();p, _ = core.bootstrap()
    context = linked.host_review(h)
    # No legacy capture may have been claimed in another area.
    need(not os.path.lexists(d.LEGACY_AREA / 'capture') and not os.path.lexists(h['AREA'] / 'capture'), 'LEGACY_CAPTURE_ALREADY_ATTEMPTED')
    recipient = h['protected'](Path('/var/lib/ouf-storage-cipher-preparation-20261106/recipient.pub'), private=True)
    need(h['digest'](recipient) == d.RECIPIENT_SHA, 'RECIPIENT_CHANGED')
    need(h['digest'](h['protected'](Path('/usr/bin/age'), limit=64 << 20)) == d.AGE_SHA, 'AGE_BINARY_CHANGED')
    self_raw = h['protected'](Path(__file__), private=True, limit=65536)
    print(json.dumps(execute(h, reader, linked, core, p, context, h['recipient'](recipient),
        args.decision_reference, h['digest'](self_raw)), sort_keys=True))


if __name__ == '__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status': 'HELD', 'reason': str(error) if type(error).__name__ in ('ValueError','Held','PropertyIssue') else type(error).__name__,
            'partialOperationPreserved': True, 'automaticReplayAllowed': False,
            'automaticRestartAllowed': False, 'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}))
        sys.exit(2)
