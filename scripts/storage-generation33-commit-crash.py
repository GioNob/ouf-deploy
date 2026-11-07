#!/usr/bin/env python3
"""Read-only ptrace observer: hold first DAT rename after durable commit marker.

Linux x86_64 only. No POKE/SETREGS, syscall substitution, detach or resume after
the selected entry. EXITKILL fails closed; the controller must SIGKILL the lab.
Semantics: https://man7.org/linux/man-pages/man2/ptrace.2.html
Scheduling is instrumented, the candidate executable and storage are not.
"""
import argparse
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import struct
import time

spec = importlib.util.spec_from_file_location('precommit', Path(__file__).with_name('storage-generation33-compaction-crash.py'))
pre = importlib.util.module_from_spec(spec); spec.loader.exec_module(pre)
require = pre.require
SEIZE, INTERRUPT, INFO, EVENTMSG, SYSCALL, PEEK = 0x4206, 0x4207, 0x420e, 0x4201, 24, 2
OPTIONS = 1 | 8 | (1 << 20)  # TRACESYSGOOD, TRACECLONE, EXITKILL
WALL = 0x40000000

def atomic_json(path, value):
    temp = path.with_suffix('.pending'); temp.write_text(json.dumps(value, indent=2)+'\n'); temp.replace(path)

def validate_phase(before, frozen, states, syncs):
    require(states and set(states.values()) == {'t'}, 'ALL_THREADS_PTRACE_STOPPED_REQUIRED')
    require(set(before) == {'.dat', '.idx'}, 'CLEAN_POSTMARKER_BASELINE_REQUIRED')
    require(set(frozen) == {'.dat', '.idx', '.cpd', '.cpx', '.cpc'} and frozen['.cpc']['bytes'] == 0,
            'COMMIT_MARKER_AND_BOTH_COPIES_REQUIRED')
    require(8 < frozen['.cpd']['bytes'] < before['.dat']['bytes'] and frozen['.cpx']['bytes'] > 0,
            'COMPLETE_NONEMPTY_COMPACTED_COPIES_REQUIRED')
    require(all(frozen[ext] == before[ext] for ext in before), 'BOTH_OLD_FILES_UNRENAMED_REQUIRED')
    require([x['kind'] for x in syncs] == ['marker', 'directory'] and all(x['returnValue'] == 0 for x in syncs),
            'MARKER_THEN_DIRECTORY_FSYNC_SUCCESS_REQUIRED')

def validate_pair(frozen, recovered):
    require(set(recovered) == {'.dat', '.idx'}, 'ROLLFORWARD_REMOVES_MARKER_AND_COPIES')
    require(recovered['.dat'] == frozen['.cpd'] and recovered['.idx'] == frozen['.cpx'],
            'EXACT_TEMPORARY_INODES_BYTES_AND_ALLOCATION_BECOME_LIVE')

class Observer:
    def __init__(self, pid, root, target, namespace_root='/data'):
        require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'LINUX_X86_64_REQUIRED')
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.ptrace.restype = ctypes.c_long
        self.libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
        self.pid, self.root, self.target = pid, root, target
        self.old_path = str(Path(namespace_root)/Path(target).with_suffix('.cpd'))
        self.new_path = str(Path(namespace_root)/target)
        self.tids, self.stopped, self.pending = set(), set(), {}
        self.syncs, self.clone_events, self.exits = [], [], []

    def ptrace(self, request, tid, address=0, data=0):
        ctypes.set_errno(0)
        ret = self.libc.ptrace(request, tid, address, data)
        if ret == -1 and ctypes.get_errno(): raise OSError(ctypes.get_errno(), 'ptrace '+str(request)+' tid '+str(tid))
        return ret

    def tasks(self):
        ids = {int(p.name) for p in (Path('/proc')/str(self.pid)/'task').iterdir()}
        require(0 < len(ids) <= 128, 'BOUNDED_TRACE_THREADS')
        return ids

    def status(self, tid):
        return dict(line.split(':', 1) for line in (Path('/proc')/str(tid)/'status').read_text().splitlines() if ':' in line)

    def wait(self, deadline):
        while time.monotonic() < deadline:
            tid, status = os.waitpid(-1, WALL | os.WNOHANG)
            if tid: return tid, status
            time.sleep(.0005)
        raise ValueError('BOUNDED_TRACE_WAIT_EXHAUSTED')

    def event(self, tid, status):
        require(tid in self.tids or int(self.status(tid)['Tgid']) == self.pid, 'EXACT_TRACE_THREAD_GROUP')
        self.tids.add(tid)
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            self.tids.discard(tid); self.stopped.discard(tid)
            self.exits.append({'tid': tid, 'signal': os.WTERMSIG(status) if os.WIFSIGNALED(status) else None,
                               'exitCode': os.WEXITSTATUS(status) if os.WIFEXITED(status) else None})
            return 'exit', 0
        require(os.WIFSTOPPED(status), 'PTRACE_STOP_REQUIRED')
        self.stopped.add(tid)
        event = status >> 16
        if event == 3:
            child = ctypes.c_ulong(); self.ptrace(EVENTMSG, tid, 0, ctypes.addressof(child))
            self.tids.add(child.value); self.clone_events.append({'parentTid': tid, 'childTid': child.value})
            require(len(self.clone_events) <= 128, 'BOUNDED_CLONE_EVENTS')
        sig = os.WSTOPSIG(status)
        return ('syscall' if sig == signal.SIGTRAP | 0x80 else 'event' if event else 'signal'), sig

    def resume(self, tid, sig=0):
        self.ptrace(SYSCALL, tid, 0, sig); self.stopped.discard(tid)

    def freeze_all(self, deadline, attach=False):
        # SEIZE autoattaches future clones; /proc plus wait events close the race.
        interrupted = set()
        while True:
            for tid in self.tasks() - self.tids:
                status = self.status(tid); tracer = int(status['TracerPid'])
                if tracer == os.getpid(): self.tids.add(tid)
                else:
                    require(attach and tracer == 0 and int(status['Tgid']) == self.pid, 'EXCLUSIVE_FIXTURE_TRACER')
                    self.ptrace(SEIZE, tid, 0, OPTIONS); self.tids.add(tid)
            for tid in self.tids - self.stopped - interrupted:
                self.ptrace(INTERRUPT, tid); interrupted.add(tid)
            if self.tasks() == self.tids == self.stopped:
                states = pre.thread_states(self.pid)
                require(set(states.values()) == {'t'} and all(int(self.status(t)['TracerPid']) == os.getpid() for t in self.tids),
                        'EVERY_THREAD_OWNED_AND_STOPPED')
                return states
            tid, status = self.wait(deadline); kind, sig = self.event(tid, status)
            require(kind != 'exit', 'NO_THREAD_EXIT_DURING_PHASE_FREEZE')
            # Initial genuine signal-delivery stops must be reinjected when armed.
            if attach and kind == 'signal': self.pending[tid] = sig

    def attach(self):
        self.freeze_all(time.monotonic()+10, attach=True)
        for tid in sorted(self.tids): self.resume(tid, self.pending.pop(tid, 0))

    def info(self, tid):
        buf = ctypes.create_string_buffer(88)
        size = self.ptrace(INFO, tid, 88, ctypes.addressof(buf)); raw = buf.raw
        require(size >= 33 and struct.unpack_from('=I', raw, 4)[0] == 0xc000003e, 'X86_64_SYSCALL_INFO_REQUIRED')
        if raw[0] == 1:
            require(size >= 80, 'COMPLETE_SYSCALL_ENTRY')
            return {'op': 'entry', 'number': struct.unpack_from('=Q', raw, 24)[0], 'args': struct.unpack_from('=6Q', raw, 32)}
        require(raw[0] == 2, 'ENTRY_OR_EXIT_INFO_REQUIRED')
        return {'op': 'exit', 'returnValue': struct.unpack_from('=q', raw, 24)[0], 'isError': bool(raw[32])}

    def string(self, tid, address):
        raw = b''
        for offset in range(0, 512, 8):
            word = self.ptrace(PEEK, tid, address+offset) & ((1 << 64)-1)
            piece = word.to_bytes(8, 'little'); raw += piece
            if b'\0' in piece: return raw.split(b'\0', 1)[0].decode('utf-8')
        raise ValueError('BOUNDED_SYSCALL_PATH_REQUIRED')

    def sync_kind(self, tid, fd):
        st = os.stat('/proc/'+str(tid)+'/fd/'+str(fd))
        for kind, path in [('marker', (self.root/self.target).with_suffix('.cpc')), ('directory', self.root)]:
            if path.exists():
                other = path.stat()
                if (st.st_dev, st.st_ino) == (other.st_dev, other.st_ino): return kind
        return None

    def observe(self, timeout=90):
        deadline = time.monotonic()+timeout
        while True:
            tid, status = self.wait(deadline); kind, sig = self.event(tid, status)
            require(kind != 'exit', 'NO_PROCESS_EXIT_BEFORE_PHASE')
            if kind == 'syscall':
                info = self.info(tid)
                if info['op'] == 'entry':
                    nr, args = info['number'], info['args']; self.pending.pop(tid, None)
                    if nr == 74:
                        sync = self.sync_kind(tid, args[0])
                        if sync: self.pending[tid] = sync
                    if nr in (82, 264, 316):
                        old, new = (args[0], args[1]) if nr == 82 else (args[1], args[3])
                        paths = (self.string(tid, old), self.string(tid, new))
                        if paths == (self.old_path, self.new_path):
                            require(nr != 316 or args[4] == 0, 'PLAIN_RENAME_REQUIRED')
                            states = self.freeze_all(time.monotonic()+5)
                            return {'tid': tid, 'number': nr, 'operation': 'entry', 'oldPath': paths[0], 'newPath': paths[1],
                                    'syscallNotResumed': True, 'threadStates': states, 'successfulSyncs': self.syncs,
                                    'cloneEvents': self.clone_events}
                else:
                    sync = self.pending.pop(tid, None)
                    if sync:
                        require(info['returnValue'] == 0 and not info['isError'], 'SUCCESSFUL_MARKER_SYNC_REQUIRED')
                        # Ignore pre-marker directory fsyncs, retain marker then its directory.
                        if sync == 'marker':
                            require(not self.syncs, 'SINGLE_COMMIT_MARKER_FSYNC')
                            self.syncs.append({'kind': sync, 'tid': tid, 'returnValue': 0})
                        elif self.syncs:
                            self.syncs.append({'kind': sync, 'tid': tid, 'returnValue': 0})
                            require(len(self.syncs) <= 2, 'SINGLE_COMMIT_DIRECTORY_FSYNC')
            self.resume(tid, sig if kind == 'signal' else 0)

    def wait_for_kill(self, timeout=90):
        deadline = time.monotonic()+timeout
        while self.tids:
            tid, status = self.wait(deadline); kind, _ = self.event(tid, status)
            require(kind == 'exit', 'ONLY_CONTROLLER_KILL_AFTER_FREEZE')
        require(self.exits and all(x['signal'] == signal.SIGKILL for x in self.exits), 'ALL_TRACED_THREADS_SIGKILL')
        return self.exits

def run(root, target, pid, container, output):
    report = {'status': 'UNQUALIFIED', 'instrumentation': 'external read-only ptrace scheduling', 'vacuumResubmissions': 0}
    try:
        require(os.geteuid() == 0 and pid > 1 and len(container) == 64 and output.is_dir(), 'EXACT_PRIVILEGED_FIXTURE_OBSERVER')
        identity = pre.process_identity(pid); require(container in identity['cgroup'], 'EXACT_CONTAINER_CGROUP_REQUIRED')
        with (Path('/proc')/str(pid)/'exe').open('rb') as stream: digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        require(digest == pre.BINARY_SHA, 'UNCHANGED_GENERATION33_BINARY_REQUIRED')
        before = pre.files(root, target); require(set(before) == {'.dat', '.idx'}, 'CLEAN_POSTMARKER_BASELINE_REQUIRED')
        report.update(processBefore=identity, binarySha256=digest, filesBefore=before)
        observer = Observer(pid, root, target); observer.attach()
        atomic_json(output/'postmarker-observer-ready.json', report)
        phase = observer.observe(); report.update(phase)
        frozen = pre.files(root, target)
        for ext in ('.cpd', '.cpx', '.cpc'):
            path = (root/target).with_suffix(ext)
            if path.exists(): (output/('postmarker-retained'+ext)).write_bytes(path.read_bytes())
        report.update(processFrozen=pre.process_identity(pid), filesFrozen=frozen)
        require(report['processFrozen'] == identity, 'SAME_FROZEN_PROCESS_REQUIRED')
        validate_phase(before, frozen, phase['threadStates'], phase['successfulSyncs'])
        require(pre.files(root, target) == frozen and pre.thread_states(pid) == phase['threadStates'], 'FROZEN_STATE_STABLE_REQUIRED')
        report['status'] = 'OBSERVED_POSTMARKER_FROZEN'
        atomic_json(output/'postmarker-freeze.json', report)
        exits = observer.wait_for_kill()
        atomic_json(output/'postmarker-observer-exit.json', {'status': 'ALL_TRACED_THREADS_KILLED', 'exits': exits})
    except Exception as error:
        report.update(status='UNQUALIFIED', failure=type(error).__name__+': '+str(error))
        atomic_json(output/'postmarker-failure.json', report)
        raise

if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('root', type=Path); p.add_argument('target'); p.add_argument('pid', type=int)
    p.add_argument('container'); p.add_argument('output', type=Path); a = p.parse_args()
    run(a.root, a.target, a.pid, a.container, a.output)
