"""Actual non-root process/NNP/capability observation, with modeled Engine I/O.

The disposable Python process stands in for application argv. This qualifies
the process/evidence composition, not Java, Docker OCI, HTTP readiness or VPS.
"""
import ctypes, errno, os, select, shutil, signal, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import Mock
ROOT = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
import test_m2_discovery_selected_runtime
from gated_creation_plan import ENTRY
from tools.m2_discovery_installation_profile import verifying_registry_binding as m


def unprivileged():
    libc = ctypes.CDLL(None, use_errno=True)
    for cap in range(64):
        if libc.prctl(24, cap, 0, 0, 0) != 0 and ctypes.get_errno() != errno.EINVAL:
            raise OSError(ctypes.get_errno(), 'DISPOSABLE_BOUNDING_CAPABILITY_DROP_FAILED')
    os.setgroups([]); os.setgid(10001); os.setuid(10001)
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(4, 1, 0, 0, 0) != 0:
        raise OSError('DISPOSABLE_NNP_OR_PROC_OBSERVABILITY_FAILED')


class NativeVerifyingBinding(unittest.TestCase):
    def prepared(self):
        self.assertEqual(os.geteuid(), 0)
        self.assertTrue(Path('/proc/self/stat').is_file(), 'NATIVE_PROC_REQUIRED_NO_SKIP')
        tmp = tempfile.TemporaryDirectory(dir=ROOT); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name); root.chmod(0o700); store = m.NativeEvidenceStore(root)
        python = str(Path(shutil.which('python3')).resolve())
        command = [python, '-I', '-B', '-S', '-c', 'import time; print("READY",flush=True); time.sleep(60)']
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=unprivileged, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        def stop():
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)
        self.addCleanup(stop)
        self.assertTrue(select.select([child.stdout], [], [], 5)[0], 'DISPOSABLE_PROCESS_NOT_READY')
        self.assertEqual(child.stdout.readline(), b'READY\n')
        request = {'Entrypoint': ENTRY, 'User': '10001:10001', 'Cmd': command}
        native = m.GatedProcessObservation(request).observe(child.pid)
        self.assertEqual(native['processKind'], 'APPLICATION_RUNNING')
        actual = {'Id': 'a'*64, 'Image': 'sha256:'+'b'*64, 'Config': {}, 'HostConfig': {}, 'Mounts': [],
            'NetworkSettings': {}, 'RestartCount': 0, 'State': {'Pid': child.pid, 'StartedAt': 'fixture',
                'Running': True, 'Paused': False, 'Restarting': False, 'Status': 'running'}}
        engine = object.__new__(m.Engine); engine.inspect = Mock(return_value=actual)
        engine.matching_configuration = Mock(side_effect=lambda t, r, a: a)
        transition = object.__new__(m.Transition); transition.context = 'c'*64
        effects = [{'phase': phase, 'state': 'APPLIED', 'intentHash': m.digest({'phase': phase})}
            for phase in m.PHASES[:12]]; effects[-1]['state'] = 'IN_FLIGHT'
        proof = {'schema': 'ouf.semantic-gated-application-release.v1', 'transitionContextHash': transition.context,
            'intentHash': effects[10]['intentHash'], 'runtimeBinding': m.Engine.runtime_binding(actual),
            'generation': native['generation'], 'processKind': 'APPLICATION_RUNNING'}
        store.publish('START_REPLACEMENT', proof); effects[10]['nativeEvidenceHash'] = m.digest(proof)
        row = {'state': 'IN_FLIGHT', 'nextPhase': 11, 'creationRequestHash': m.digest(request), 'effects': effects}
        transition.read = Mock(return_value=row)
        return m.VerifyingRegistryBinding(engine, transition, request, store), child, store

    def test_real_released_process_passes_before_verification_receipt_exists(self):
        reader, child, store = self.prepared(); result = reader.observe()
        self.assertEqual(result['runtimeBinding']['pid'], child.pid)
        for key in ('nonRootIdentityVerified', 'capabilitiesEmpty', 'noNewPrivileges'):
            self.assertIs(result['process'][key], True)
        self.assertFalse(store.path('VERIFY_APPLICATION').exists())

    def test_same_pid_with_unreviewed_argv_is_denied_without_receipt_or_repair(self):
        reader, _, store = self.prepared()
        reader.process.application_args = ['unreviewed-application-arguments']
        with self.assertRaisesRegex(ValueError, 'SAME_RELEASED_RUNNING_REGISTRY'): reader.observe()
        self.assertFalse(store.path('VERIFY_APPLICATION').exists())


if __name__ == '__main__': unittest.main()
