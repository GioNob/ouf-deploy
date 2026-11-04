#!/usr/bin/env python3
"""Observe then freeze the unchanged fixture binary before compaction commit.

The controller kills it only after the frozen-state evidence is retained.
No retry, storage repair, injected marker, or instrumented server binary.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import time

BINARY_SHA = 'c301b4f487f17f4d9b8dfe1b26885ec4ea6141e1ace73b8dfaadff70bd714dfc'

def require(ok, code):
    if not ok: raise ValueError(code)

def sha(raw): return hashlib.sha256(raw).hexdigest()

def process_identity(pid):
    root = Path('/proc') / str(pid)
    stat = (root / 'stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': int(pid), 'startTicks': int(stat[19]),
            'networkNamespace': os.readlink(root / 'ns/net'),
            'cgroup': (root / 'cgroup').read_text()}

def thread_states(pid):
    tasks = sorted((Path('/proc') / str(pid) / 'task').iterdir())
    require(0 < len(tasks) <= 128, 'BOUNDED_VOLUME_THREADS_REQUIRED')
    return {p.name: (p / 'stat').read_text().rsplit(')', 1)[1].split()[0] for p in tasks}

def files(root, target, output=None):
    require(re.fullmatch(r'ouf-identity-fixture_[1-9][0-9]*\.dat', target), 'EXACT_COMPACTION_TARGET_REQUIRED')
    require(root.is_dir() and not root.is_symlink(), 'REGULAR_VOLUME_ROOT_REQUIRED')
    result = {}
    for ext in ('.dat', '.idx', '.cpd', '.cpx', '.cpc'):
        p = (root / target).with_suffix(ext)
        if not p.exists():
            require(not p.is_symlink(), 'NO_DANGLING_COMPACTION_SYMLINK'); continue
        require(p.is_file() and not p.is_symlink() and p.stat().st_size <= 33*1024*1024, 'BOUNDED_REGULAR_COMPACTION_FILE')
        st = p.stat(); raw = p.read_bytes()
        require(len(raw) == st.st_size, 'STABLE_COMPACTION_FILE_REQUIRED')
        result[ext] = {'bytes': len(raw), 'sha256': sha(raw), 'inode': st.st_ino,
                        'device': st.st_dev, 'allocatedBytes': st.st_blocks*512}
        if output is not None and ext in ('.cpd', '.cpx', '.cpc'):
            # Original stopped temporary bytes, including ambiguous cases.
            (output / ('precommit-retained'+ext)).write_bytes(raw)
    return result

def validate_phase(before, frozen, states):
    require(states and all(s == 'T' for s in states.values()), 'ALL_VOLUME_THREADS_STOPPED_REQUIRED')
    require(set(before) == {'.dat', '.idx'}, 'CLEAN_PRECOMMIT_BASELINE_REQUIRED')
    require('.cpc' not in frozen, 'COMMIT_MARKER_ABSENT_REQUIRED')
    require('.cpd' in frozen and 8 < frozen['.cpd']['bytes'] < before['.dat']['bytes'], 'OBSERVED_COMPACTION_COPY_REQUIRED')
    require(all(frozen.get(ext) == before[ext] for ext in ('.dat', '.idx')), 'NO_LIVE_DAT_IDX_RENAME_OR_CHANGE_REQUIRED')

def validate_rollback(before, after, *, gated=False):
    require(not after['openDeletedFixtureFiles'], 'NO_OPEN_DELETED_COMPACTION_FILES')
    for key in ('datFiles', 'indexes', 'datBytes', 'datAllocatedBytes', 'orphanPayloadFiles'):
        require(before[key] == after[key], 'EXACT_PRECOMMIT_STORAGE_AND_ALLOCATION_REQUIRED')
    if not gated:
        require(not after['temporaryCompactionFiles'], 'ABANDONED_COMPACTION_TEMPORARIES_REMOVED_REQUIRED')

def freeze(root, target, pid, container, output):
    require(os.geteuid() == 0 and re.fullmatch(r'[0-9a-f]{64}', container), 'EXACT_PRIVILEGED_FIXTURE_OBSERVER_REQUIRED')
    require(pid > 1 and output.is_dir() and not output.is_symlink(), 'EXACT_OBSERVER_ARGUMENTS_REQUIRED')
    report = {'status': 'UNQUALIFIED', 'signal': 'SIGSTOP', 'vacuumResubmissions': 0}
    try:
        identity = process_identity(pid)
        require(container in identity['cgroup'], 'EXACT_CONTAINER_CGROUP_REQUIRED')
        with (Path('/proc')/str(pid)/'exe').open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        require(digest == BINARY_SHA, 'UNCHANGED_GENERATION33_BINARY_REQUIRED')
        before = files(root, target)
        require(set(before) == {'.dat', '.idx'}, 'CLEAN_PRECOMMIT_BASELINE_REQUIRED')
        report.update(processBefore=identity, binarySha256=digest, filesBefore=before)
        (output/'precommit-observer-ready.json').write_text(json.dumps(report))
        deadline = time.monotonic()+45
        cpd = (root/target).with_suffix('.cpd')
        while time.monotonic() < deadline:
            if cpd.exists() and cpd.stat().st_size > 8: break
            time.sleep(.001)
        else: raise ValueError('PRECOMMIT_OBSERVATION_BUDGET_EXHAUSTED')
        require(process_identity(pid) == identity, 'SAME_PROCESS_BEFORE_SIGNAL_REQUIRED')
        os.kill(pid, signal.SIGSTOP)
        deadline = time.monotonic()+3
        while True:
            states = thread_states(pid)
            if all(s == 'T' for s in states.values()): break
            require(time.monotonic() < deadline, 'VOLUME_STOP_BUDGET_EXHAUSTED'); time.sleep(.005)
        frozen = files(root, target, output)
        report.update(processFrozen=process_identity(pid), threadStates=states, filesFrozen=frozen)
        require(report['processFrozen'] == identity, 'SAME_FROZEN_PROCESS_REQUIRED')
        validate_phase(before, frozen, states)
        require(files(root,target) == frozen and thread_states(pid) == states, 'FROZEN_STATE_STABLE_REQUIRED')
        report['status'] = 'OBSERVED_PRECOMMIT_FROZEN'
    except Exception as error:
        report['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        (output/'precommit-freeze.json').write_text(json.dumps(report, indent=2)+'\n')

if __name__ == '__main__':
    p = argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('target');p.add_argument('pid',type=int)
    p.add_argument('container');p.add_argument('output',type=Path);a=p.parse_args()
    freeze(a.root,a.target,a.pid,a.container,a.output)
