"""Offline checks of the emitted D-053.3 sources and journal compatibility."""
from pathlib import Path
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_runtime_v52_epochs as V52
from r3_sealed_inputs import sealed_legacy_inputs
import test_semantic_provider_r3_v15 as V15
from tools.semantic_provider_r3 import compose as C, upgrade as U
from tools.semantic_provider_r3.driver_denial_overlay_v16 import EPOCHS, RUNTIME, sources_v16


CID = V52.CID
PREFIX = b'SEMANTIC_PREEXEC_HOOK=DENIED '
MARKER = PREFIX + b'DRIVER_GATE_FAILED\n'
AUTH = 'tools/semantic_provider_operation/authorization.py'
BOOT = '00112233-4455-6677-8899-aabbccddeeff'
ORIGINAL = {p: V15.V13.V12.blob(p) for p in (RUNTIME, EPOCHS, AUTH)}
EMITTED = sources_v16(ORIGINAL, C.SOURCE_MAP_V15)


def runtime(emitted=EMITTED):
    module = ModuleType('driver_denial')
    # The pipe test needs real Linux IO, but none of these fixtures takes a native flock.
    with patch.dict(sys.modules, {'fcntl': ModuleType('fcntl')}):
        exec(compile(emitted[RUNTIME], RUNTIME, 'exec'), module.__dict__)
    return module


def journal(epochs, n, **extra):
    return dict(schema=epochs.JOURNAL_SCHEMA, containerId=CID, epoch=n, bootId=BOOT,
                authorizationSha256='a' * 64, configurationHash='b' * 64, state='FAILED',
                runtimeRoot='/run/fixture', bundleHash=None, driverHash=None, generation=None,
                openedAt=1, failure='ADMISSION_OR_DRIVER_FAILED', **extra)


class Composition(unittest.TestCase):
    def test_overlay_is_deterministic_and_confined_to_two_logical_paths(self):
        self.assertEqual(EMITTED, sources_v16(ORIGINAL, C.SOURCE_MAP_V15))
        self.assertEqual(set(EMITTED), set(ORIGINAL))
        self.assertEqual({p for p in ORIGINAL if ORIGINAL[p] != EMITTED[p]}, {RUNTIME, EPOCHS})
        drift = ORIGINAL | {EPOCHS: ORIGINAL[EPOCHS] + b'\n    return value\n'}
        with self.assertRaisesRegex(C.A.OperationDenied, '^R3_V16_SOURCE_CONTRACT_DRIFT$'):
            sources_v16(drift, C.SOURCE_MAP_V15)

    def test_frozen_v15_input_and_output_bytes(self):
        # Captured at c1c17d55 before adding the v16 overlay.
        golden = ('a0b848c3df996453006069c99d7dd67d792e4239035167f91293814ae3471a4a',
                  '88b0e6d355bf04a3cb4e3a49dfa822886de3281b6092a9c858dee96a33b220a8',
                  '2a3025f16933f4d3269f16ef8e522e13e819ebddb5329a3b0023406cff6fe3ce',
                  '6b36c48005502ac87a53d07305ddc43c3ec7024d16c171ca237380e7d39d1ddb')
        with sealed_legacy_inputs(V15.V13.V12):
            inputs, before = V15.fixture()
        result = C.compose(inputs, 15, sequence=15, supersedes=C.sha(before['authorization']))
        self.assertEqual(tuple(C.sha(C.canonical(result[k])) for k in ('hashes', 'inputHashes', 'audit', 'layout')),
                         golden)


class Journals(unittest.TestCase):
    def setUp(self):
        self.old = C.contract_module(ORIGINAL[EPOCHS], 'v15_epochs')
        self.new = C.contract_module(EMITTED[EPOCHS], 'v16_epochs')

    def test_closed_v2_and_v3_schemas(self):
        old = journal(self.old, 1)
        new = journal(self.new, 2, driverDenial={'phase': 'start', 'code': 'DENIED'})
        for row in (old, new, new | {'driverDenial': None}):
            self.assertEqual(self.new.validate_journal(C.canonical(row), CID, row['epoch']), row)
        for row in (old | {'driverDenial': None}, {k: v for k, v in new.items() if k != 'driverDenial'},
                    new | {'driverDenial': {'phase': 'start', 'code': 'DENIED', 'stderr': 'foreign'}},
                    new | {'driverDenial': {'phase': 'prepare', 'code': 'DENIED'}},
                    new | {'driverDenial': {'phase': 'hook', 'code': 'D' * 81}},
                    new | {'driverDenial': {'phase': 'hook', 'code': 'denied'}},
                    new | {'state': 'DELETING', 'failure': None}):
            with self.subTest(row=row), self.assertRaises(C.A.OperationDenied):
                self.new.validate_journal(C.canonical(row), CID, row['epoch'])

    def test_installed_upgrade_reader_checks_full_mixed_history(self):
        new_runtime, old_runtime = runtime(), runtime(ORIGINAL)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / CID
            cfg = dict(registryRoot=str(root), candidates={CID: {}}, authorizationModule={'path': AUTH},
                       epochsModule={'path': EPOCHS})
            rows = [journal(self.old, 1), journal(self.new, 2, driverDenial=None), journal(self.new, 3, driverDenial=None)]

            def pointer(row):
                (base / 'current').write_bytes(C.canonical(dict(epoch=row['epoch'], journalSha256=C.sha(C.canonical(row)))))

            for row in rows:
                folder = base / 'epochs' / str(row['epoch'])
                folder.mkdir(parents=True)
                (folder / 'adapter.json').write_bytes(C.canonical(row))
            pointer(rows[-1])
            args = SimpleNamespace(docker='/docker', docker_sha256='a' * 64, docker_socket='unix:///docker.sock')
            frame = {'State': {'Status': 'exited', 'Running': False, 'Pid': 0}}

            def operation_modules(module, blobs):
                with patch.object(module, 'bound_bytes', side_effect=lambda value: blobs[value['path']]):
                    auth, epochs = module.operation_modules(cfg)
                epochs.directory = lambda _: None
                epochs.file_bytes = Path.read_bytes
                return auth, epochs

            for module, blobs in ((new_runtime, EMITTED), (old_runtime, ORIGINAL)):
                loaded = operation_modules(module, blobs)
                module.operation_modules = lambda _, loaded=loaded: loaded
                module.read = Path.read_bytes
                module.private_directory = lambda _: None
            custody = SimpleNamespace(custody=lambda path, _: (path.read_bytes(), None))
            with patch.object(U.V, 'private_directory'), patch.object(U.I, 'native_switch', return_value=custody), \
                    patch.object(U.V, 'docker_inspect', return_value=frame) as docker:
                report = U.stopped_provider(new_runtime, cfg, args)[CID]
                self.assertEqual(report['current'], rows[-1])
                self.assertEqual(report['journalHashes'], {str(row['epoch']): C.sha(C.canonical(row)) for row in rows})
                actual = new_runtime.epoch_inventory(base, new_runtime.operation_modules(cfg)[1], rows[-1])
                self.assertEqual(sorted(actual, key=lambda row: row['epoch']), rows)
                docker.reset_mock()
                with self.assertRaisesRegex(old_runtime.operation_modules(cfg)[0].OperationDenied,
                                            '^EXACT_EPOCH_JOURNAL_REQUIRED$'):
                    U.stopped_provider(old_runtime, cfg, args)
                docker.assert_not_called()

                # A later v2 current still cannot mask a retained v3 journal.
                latest = journal(self.old, 3)
                (base / 'epochs/3/adapter.json').write_bytes(C.canonical(latest))
                pointer(latest)
                with self.assertRaisesRegex(old_runtime.operation_modules(cfg)[0].OperationDenied,
                                            '^EXACT_EPOCH_JOURNAL_REQUIRED$'):
                    U.stopped_provider(old_runtime, cfg, args)
                docker.assert_not_called()


class Start(unittest.TestCase):
    run_op = V52.PortableFailedCleanup.run_op
    denied = V52.PortableFailedCleanup.denied

    def setUp(self):
        V52.PortableAdmissionSection.setUp(self)
        self.r = runtime()
        self.r.time = SimpleNamespace(monotonic=lambda: self.now)
        self.record.update(schema='ouf.semantic-docker-runtime-journal.v3', driverDenial=None)
        self.driver_phase = 'start'
        self.stderr = MARKER
        self.readback_fails = False
        self.driver_timeout = False
        self.driver_caps = []
        self.enterContext(patch.object(self.r, 'driver_result', side_effect=self.driver_result))

    def simulate(self, args, **options):
        if self.readback_fails and args[:1] == ['/runc'] and self.state['status'] == 'running':
            return subprocess.CompletedProcess(args, 1)
        return V52.PortableAdmissionSection.simulate(self, args, **options)

    def driver_result(self, args, phase, state, timeout):
        self.driver_caps.append((phase, timeout))
        self.assertEqual(state, self.state if phase == 'hook' else None)
        if phase == self.driver_phase:
            if self.driver_timeout:
                raise subprocess.TimeoutExpired('PRIVATE_ARGV_SENTINEL', timeout, stderr=MARKER)
            return 1, True, self.r.driver_denial(1, self.stderr, True)
        if phase == 'start':
            self.state['status'] = 'running'
        return 0, True, None

    def test_hook_denial_keeps_public_reason(self):
        self.driver_phase = 'hook'
        self.denied('start', 'OCI_ADMISSION_GATE_DENIED')
        self.assertEqual(self.driver_caps, [('hook', 10)])
        self.assertEqual(self.record['driverDenial'], {'phase': 'hook', 'code': 'DRIVER_GATE_FAILED'})
        self.assertEqual(self.record['failure'], 'OCI_ADMISSION_GATE_DENIED')

    def test_start_denial_keeps_public_reason(self):
        self.denied('start', 'ADMISSION_OR_DRIVER_FAILED')
        self.assertEqual(self.driver_caps, [('hook', 10), ('start', 20)])
        self.assertEqual(self.record['driverDenial'], {'phase': 'start', 'code': 'DRIVER_GATE_FAILED'})
        self.assertEqual(self.record['failure'], 'ADMISSION_OR_DRIVER_FAILED')

    def test_foreign_stderr_keeps_only_public_reason(self):
        for stderr in (MARKER + b'PRIVATE_OUTPUT_SENTINEL\n', MARKER * 2, MARKER + b'X' * 16385):
            with self.subTest(length=len(stderr)):
                self.record.update(state='CREATED', failure=None, driverDenial=None)
                self.stderr = stderr
                self.denied('start', 'ADMISSION_OR_DRIVER_FAILED')
                self.assertEqual(self.record['failure'], 'ADMISSION_OR_DRIVER_FAILED')
                self.assertIsNone(self.record['driverDenial'])

    def test_driver_timeout_keeps_only_public_reason(self):
        self.driver_timeout = True
        self.denied('start', 'DOCKER_RUNTIME_OPERATION_UNPROVEN')
        self.assertEqual(self.record['failure'], 'DOCKER_RUNTIME_OPERATION_UNPROVEN')
        self.assertIsNone(self.record['driverDenial'])

    def test_runc_readback_failure_is_distinct(self):
        self.driver_phase = None
        self.readback_fails = True
        self.denied('start', 'STARTED_RUNTIME_STATE_UNPROVEN')
        self.assertEqual(self.record['failure'], 'STARTED_RUNTIME_STATE_UNPROVEN')
        self.assertIsNone(self.record['driverDenial'])


class Cleanup(unittest.TestCase):
    run_op = V52.PortableFailedCleanup.run_op
    denied = V52.PortableFailedCleanup.denied
    simulate = V52.PortableFailedCleanup.simulate
    consumed = V52.PortableFailedCleanup.consumed
    prepared = V52.PortableFailedCleanup.prepared

    def setUp(self):
        V52.PortableFailedCleanup.setUp(self)
        self.r = runtime()
        self.record.update(schema='ouf.semantic-docker-runtime-journal.v3',
                           driverDenial={'phase': 'start', 'code': 'DRIVER_GATE_FAILED'})
        self.prepared()

    def check_cleanup(self):
        self.assertEqual(self.record['state'], 'DELETING')
        self.assertIsNone(self.record['driverDenial'])
        self.assertIsNone(self.record['failure'])

    def test_cleanup_restores_original_failed_record(self):
        self.quiesce.side_effect = lambda _: self.check_cleanup()
        self.assertEqual(self.run_op('delete'), 0)
        self.assertEqual(self.transitions, ['DELETING', 'FAILED'])
        self.assertEqual(self.record, self.before)

    def test_partial_cleanup_also_restores_original_failed_record(self):
        def deny(_):
            self.check_cleanup()
            raise self.r.Denied('LEASE_QUIESCENCE_UNPROVEN')
        self.quiesce.side_effect = deny
        self.denied('delete', 'FAILED_PREPARED_EPOCH_REQUIRES_RECOVERY')
        self.assertEqual(self.transitions, ['DELETING', 'FAILED'])
        self.assertEqual(self.record, self.before)

    def test_v2_cleanup_keeps_historical_shape(self):
        self.record['schema'] = 'ouf.semantic-docker-runtime-journal.v2'
        del self.record['driverDenial']
        before = dict(self.record)
        self.quiesce.side_effect = lambda _: self.assertNotIn('driverDenial', self.record)
        self.assertEqual(self.run_op('delete'), 0)
        self.assertEqual(self.transitions, ['DELETING', 'FAILED'])
        self.assertEqual(self.record, before)


class Create(unittest.TestCase):
    run_op = V52.PortableFailedCleanup.run_op
    denied = V52.PortableFailedCleanup.denied
    simulate = V52.PortableFailedCleanup.simulate

    def test_opening_is_v3_with_null_detail(self):
        V52.PortableFailedCleanup.setUp(self)
        self.r = runtime()
        self.record = None
        self.folder.parent.mkdir(parents=True)
        self.cfg['limits'] = {'maxEpochsPerHour': 6}
        self.cfg['candidates'][CID]['bundleParents'] = []
        epochs = C.contract_module(EMITTED[EPOCHS], 'create_v16_epochs')
        self.epochs = SimpleNamespace(current=lambda *_: self.record, boot_id=lambda: BOOT,
            JOURNAL_SCHEMA=epochs.JOURNAL_SCHEMA, MAX_EPOCH=epochs.MAX_EPOCH, validate_journal=epochs.validate_journal)

        path = str(self.folder / 'adapter.json')

        def current(*_):
            self.record = epochs.validate_journal(self.files[path], CID, 1)

        # Stop after the opening publication through the ordinary bundle guard.
        with patch.object(self.r, 'sync_directory'), patch.object(self.r, 'replace_cas', side_effect=current):
            self.denied('create', 'OCI_BUNDLE_PARENT_DRIFT')
        opened = epochs.validate_journal(self.files[path], CID, 1)
        self.assertEqual(opened['schema'], 'ouf.semantic-docker-runtime-journal.v3')
        self.assertEqual(opened['state'], 'OPENING')
        self.assertIsNone(opened['driverDenial'])
        self.assertEqual(self.record['state'], 'FAILED')
        self.assertIsNone(self.record['driverDenial'])


class Capture(unittest.TestCase):
    def test_extract_only_complete_unique_marker(self):
        extract = runtime().driver_denial
        self.assertEqual(extract(1, MARKER, True), 'DRIVER_GATE_FAILED')
        self.assertEqual(extract(1, PREFIX + b'X' * 80 + b'\n', True), 'X' * 80)
        self.assertIsNone(extract(0, MARKER, True))
        self.assertIsNone(extract(-9, MARKER, True))
        self.assertIsNone(extract(1, MARKER, False))
        for raw in (b'', MARKER * 2, b'foreign\n' + MARKER, MARKER + b' ', MARKER[:-1],
                    MARKER + b'X' * 16385, PREFIX + b'X' * 81 + b'\n', PREFIX + b'x\n', PREFIX + b'\xff\n'):
            with self.subTest(prefix=raw[:100]):
                self.assertIsNone(extract(1, raw, True))

    @unittest.skipUnless(sys.platform == 'linux', 'anonymous subprocess pipe selector requires Linux')
    def test_real_bounded_capture_and_timeout(self):
        run = runtime().driver_result

        def child(body):
            return [sys.executable, '-I', '-B', '-c', 'import sys, time; ' + body]

        fail = f'sys.stderr.buffer.write({MARKER!r}); sys.exit(1)'
        self.assertEqual(run(child(fail), 'start', None, 5), (1, True, 'DRIVER_GATE_FAILED'))
        verify_input = 'assert sys.stdin.buffer.read() == b\'{"id":"fixture"}\'; '
        self.assertEqual(run(child(verify_input + fail), 'hook', {'id': 'fixture'}, 5),
                         (1, True, 'DRIVER_GATE_FAILED'))
        oversized = f'sys.stderr.buffer.write({MARKER!r} + b"X" * 1000000); sys.exit(1)'
        self.assertEqual(run(child(oversized), 'start', None, 5), (1, True, None))
        noisy = 'sys.stdout.buffer.write(b"X" * 16385); ' + fail
        self.assertEqual(run(child(noisy), 'start', None, 5), (1, False, None))
        sleeping = f'sys.stderr.buffer.write({MARKER!r}); sys.stderr.flush(); time.sleep(30)'
        with self.assertRaises(subprocess.TimeoutExpired) as timed_out:
            run(child(sleeping), 'start', None, 0.25)
        self.assertEqual(timed_out.exception.cmd, 'start')
        self.assertIsNone(timed_out.exception.stderr)


if __name__ == '__main__':
    unittest.main()
