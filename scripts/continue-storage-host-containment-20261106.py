#!/usr/bin/env python3
"""Explicit, separately decided continuation after the exact read-only slice HOLD.
Does not reuse, edit or replay the original operation area or its time allowance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import types

PRIOR = Path('/var/lib/ouf-storage-host-containment-20261106-v1')
AREA = Path('/var/lib/ouf-storage-host-continuation-20261106-v1')
OLD_PATH = Path('/var/lib/ouf-storage-host-containment-20261106.py')
OLD_SHA = '6d5e41d71150c8e59394002473e6eee728981f540bad94a09fd633f493004004'
FIXED_PATH = Path('/var/lib/ouf-storage-host-containment-fixed-20261106.py')
FIXED_SHA = '05f4e5166a4818d6d6b5a33651e4d4d39888245b2ebe0a3d1ae07a9c28a148ec'
PINNED = {
    'claim.private.json': '622a6a5291c8b9e6ef85bae175d92b23b207b99ad3ec9b1b4d954d0c71d7645b',
    'command-001.private.json': '9ba599f8ea1938ff3c79c13bab7b2ca5b314dfe199ecf4e47df0a4677b0da67f',
    'reviewed-draft.private.json': 'c4d59b3894f59d6679f11d48dbec2a3d7f5cbba6c8aa89bbee78b63e86475d0a',
}
OLD_DECISION = 'GIOVANNI-NONPROD-HOST-CONTAIN-20261106-01'
DECISION = 'GIOVANNI-NONPROD-HOST-CONTINUE-20261106-01'


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def load_pinned(path, sha):
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
    m = types.ModuleType('pinned_' + path.stem)
    m.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), m.__dict__)
    return m


class RetainedReads:
    """Feeds recorded replies to old pure validation; never invokes a process."""
    def __init__(self, records):
        self.records, self.calls, self.bytes, self.cgroups = records, 0, 0, {}

    def run(self, binary, args, mutation=False):
        need(not mutation and self.calls < len(self.records), 'PRIOR_READ_SEQUENCE_ONLY')
        row = self.records[self.calls]
        need(row['binary'] == binary and row['args'] == args and row['returncode'] == 0, 'PRIOR_READ_SEQUENCE_MISMATCH')
        need(isinstance(row['stdout'], str) and isinstance(row['stderr'], str), 'PRIOR_OUTPUT_TYPES')
        size = len(row['stdout'].encode()) + len(row['stderr'].encode())
        need(size <= 1 << 20, 'PRIOR_OUTPUT_LIMIT')
        self.calls += 1
        self.bytes += size
        need(self.bytes <= 32 << 20, 'PRIOR_TOTAL_OUTPUT_LIMIT')
        return row['stdout']


def prior_readback(h, p, old):
    s = PRIOR.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o700, 'PRIOR_PRIVATE_DIRECTORY')
    expected = {'claim.private.json', 'reviewed-draft.private.json'} | {'command-%03d.private.json' % n for n in range(1, 20)}
    names = set()
    with os.scandir(PRIOR) as scan:
        for entry in scan:
            names.add(entry.name)
            need(len(names) <= len(expected), 'PRIOR_SCOPE_CHANGED')
    need(names == expected, 'PRIOR_SCOPE_CHANGED')
    raws = {name: h['protected'](PRIOR / name, private=True, limit=2 << 20) for name in sorted(expected)}
    hashes = {name: h['digest'](raw) for name, raw in raws.items()}
    need(all(hashes[name] == sha for name, sha in PINNED.items()), 'PRIOR_PINNED_RECEIPT_CHANGED')
    claim = h['decode'](raws['claim.private.json'])
    draft = h['decode'](raws['reviewed-draft.private.json'])
    need(claim['decisionReference'] == OLD_DECISION and claim['attempts'] == 1 and
         claim['maximumSeconds'] == 600 and claim['maximumCliCalls'] == 256 and
         claim['maximumCliBytes'] == 32 << 20 and claim['draftSha256'] == hashes['reviewed-draft.private.json'], 'PRIOR_CLAIM_SCOPE')
    need(claim['priorInputSha256'] == draft['priorInputSha256'] and
         claim['legacyValidUntilEpoch'] == draft['legacyValidUntilEpoch'], 'PRIOR_CLAIM_BINDING')
    need(draft['timerUnits'] == list(p.TIMERS) and draft['serviceUnits'] == list(p.SERVICES) + [p.REGISTRY], 'EXACT_HOST_SCOPE')
    need(all(f.get('reason') == 'PROPERTY_CARDINALITY' and f.get('property') in ('ExecStop', 'ExecStopPost') and f.get('occurrences') == 0 for f in draft['findings']), 'OTHER_FINDINGS')
    records = [h['decode'](raws['command-%03d.private.json' % n]) for n in range(1, 20)]
    retained = RetainedReads(records)
    old.check_units(p, old.show(p, retained), draft)
    for unit in tuple(p.SERVICES) + (p.REGISTRY,):
        old.empty_stop_hooks(retained, unit)
    try:
        old.bind_cgroups(p, retained, old_rows(records[0], p))
    except ValueError as error:
        need(str(error) == 'SLICE_NAME_REQUIRED' and retained.calls == 19, 'EXACT_PREMUTATION_HOLD_REQUIRED')
    else:
        raise ValueError('EXPECTED_SLICE_HOLD_NOT_REPRODUCED')
    return draft, hashes, retained.bytes


def old_rows(first, p):
    previous = p.PROPS
    try:
        p.PROPS = tuple(dict.fromkeys(previous + ('RefuseManualStop', 'OnFailure', 'OnSuccess', 'ControlPID', 'Slice')))
        return {p.one(row, 'Id'): row for row in p.property_rows(first['stdout'])}
    finally:
        p.PROPS = previous


def apply(h, p, fixed, old, decision):
    need(decision == DECISION, 'EXACT_CONTINUATION_DECISION_REQUIRED')
    need(not os.path.lexists(AREA), 'CONTINUATION_ALREADY_CLAIMED')
    draft, hashes, prior_bytes = prior_readback(h, p, old)
    need(int(time.time()) + 5400 < draft['legacyValidUntilEpoch'], 'ORIGINAL_PLAN_WINDOW_INSUFFICIENT')
    for path, sha in draft['priorInputSha256'].items():
        need(h['digest'](h['protected'](Path(path), private=True)) == sha, 'PRIOR_INPUT_CHANGED')
    legacy = h['decode'](h['protected'](Path(next(iter(p.PRIOR))), private=True))
    sources = sorted(legacy['runtimeSources'])
    need(len(sources) == 5, 'EXACT_RUNTIME_SOURCES')
    fd = h['runtime_parent'](AREA);os.close(fd)
    AREA.mkdir(mode=0o700)
    claim = {'schema': 'ouf.storage-host-continuation-claim.v1', 'decisionReference': decision,
        'priorDecisionReference': OLD_DECISION, 'priorJournalSha256': hashes,
        'priorAttemptConsumed': True, 'continuationAttempts': 1, 'priorReadCalls': 19,
        'priorCliOutputBytes': prior_bytes, 'maximumCumulativeCliCalls': 256,
        'maximumCumulativeCliBytes': 32 << 20, 'priorTimeAllowanceChargedSeconds': 600,
        'separateContinuationSeconds': 600, 'maximumCumulativeActiveAllowanceSeconds': 1200,
        'legacyValidUntilEpoch': draft['legacyValidUntilEpoch'], 'automaticReplayAllowed': False,
        'runtimeAuthorityIssued': False}
    h['new'](AREA / 'claim.private.json', h['canonical'](claim))
    h['new'](AREA / 'reviewed-draft.private.json', h['canonical'](draft))
    run = fixed.Runner(h, AREA)
    run.calls, run.bytes = 19, prior_bytes  # Prior reads remain charged; journal starts at020.
    result = fixed.containment(h, p, draft, AREA, run, decision, sources)
    # Re-read all old evidence after the operation without ever editing it.
    need(all(h['digest'](h['protected'](PRIOR / name, private=True, limit=2 << 20)) == sha for name, sha in hashes.items()), 'PRIOR_JOURNAL_CHANGED')
    result = dict(result, schema='ouf.storage-host-continuation-result.v1',
        priorAttemptPreserved=True, priorReadCalls=19, priorCliOutputBytes=prior_bytes,
        newCommandCalls=run.calls - 19, cumulativeCommandCalls=run.calls,
        priorTimeAllowanceChargedSeconds=600, separateContinuationSeconds=600,
        maximumCumulativeActiveAllowanceSeconds=1200, oldProviderReadsReissued=False,
        freshProviderPreflightPerformed=True)
    h['new'](AREA / 'continuation-result.json', h['canonical'](result))
    return result


if __name__ == '__main__':
    try:
        need(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode, 'ROOT_ISOLATED_REQUIRED')
        parser = argparse.ArgumentParser()
        parser.add_argument('--decision-reference', required=True)
        parser.add_argument('--exclusive-operator-maintenance', action='store_true', required=True)
        parser.add_argument('--nonproduction-test-state', action='store_true', required=True)
        args = parser.parse_args()
        fixed, old = load_pinned(FIXED_PATH, FIXED_SHA), load_pinned(OLD_PATH, OLD_SHA)
        p, h = fixed.bootstrap()
        print(json.dumps(apply(h, p, fixed, old, args.decision_reference), sort_keys=True))
    except Exception as error:
        print(json.dumps({'status': 'HELD', 'reason': str(error) if isinstance(error, ValueError) else type(error).__name__,
            'partialOperationPreserved': True, 'automaticReplayAllowed': False,
            'automaticRestartAllowed': False, 'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}))
        sys.exit(2)
