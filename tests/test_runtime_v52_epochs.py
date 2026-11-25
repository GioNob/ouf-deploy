"""v5.2 native custody/authorization with simulated OCI subprocess boundaries.

Only ephemeral test authorization signatures are produced. No Docker, network,
nft, installed configuration or production key is used.
"""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import call, patch, Mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'tools/semantic_runtime_v52/semantic_provider_docker_runtime_v52.py'
CID, PEER = 'a'*64, 'b'*64
NATIVE = os.environ.get('OUF_RUNTIME_V52_NATIVE') == '1'
if NATIVE and (sys.platform != 'linux' or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError('OUF_RUNTIME_V52_NATIVE requires Linux root:root; refusing to skip')


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def sha(raw): return hashlib.sha256(raw).hexdigest()


def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


operation_fixture = load(ROOT/'tests/test_semantic_provider_operation.py', 'v52_operation_fixture')
grant_fixture = load(ROOT/'tests/test_semantic_provider_admission_v2_preparer.py', 'v52_grant_fixture')


class PortableContracts(unittest.TestCase):
    def runtime(self):
        with patch.dict(sys.modules, {'fcntl': types.ModuleType('fcntl')}):
            return load(SOURCE, 'runtime_v52_portable')

    def test_no_arming_signing_or_mutable_path_import(self):
        tree = ast.parse(SOURCE.read_text())
        names = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertFalse(names & {'sign', 'signing_bytes', 'spec_from_file_location', 'insert'})
        self.assertNotIn('select_arming', SOURCE.read_text())
        self.assertIn("'ouf.semantic-docker-runtime-adapter.v5.2'", SOURCE.read_text())

    def test_real_v7_validator_rejects_legacy_and_open_schema(self):
        driver = grant_fixture.d
        good = grant_fixture.grant()
        self.assertEqual(driver.validate(encoded(good)), good)
        for change in ({'schema': 'ouf.semantic-preexec-driver.v6'}, {'extra': True},
                       {'operationBinding': {**good['operationBinding'], 'epoch': True}}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                driver.validate(encoded({**good, **change}))

    def test_public_error_redaction(self):
        # Linux's fcntl is not available on Windows; no native function executes.
        runtime = self.runtime()
        self.assertEqual(runtime.public(ValueError('/private/sentinel')), 'DOCKER_RUNTIME_OPERATION_UNPROVEN')
        self.assertEqual(runtime.public(runtime.Denied('EPOCH_STILL_OPEN')), 'EPOCH_STILL_OPEN')

    def test_admission_wait_exceeds_section_and_margin_inside_r3_default(self):
        runtime = self.runtime()
        budget = runtime.ADMISSION_SECTION_BUDGET_SECONDS
        wait = runtime.ADMISSION_SCHEDULE_TIMEOUT_SECONDS
        self.assertEqual(budget, 20 + 10 + 20 + 10)
        self.assertGreater(wait, budget + runtime.ADMISSION_SCHEDULE_MARGIN_SECONDS)
        # Read the actual parser default without invoking native observation.
        tree = ast.parse((ROOT/'tools/semantic_provider_r3/operate.py').read_bytes())
        timeout = next(n for n in ast.walk(tree) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute) and n.func.attr == 'add_argument'
            and n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value == '--timeout-seconds')
        outer = next(k.value.value for k in timeout.keywords if k.arg == 'default')
        self.assertEqual(outer, 180)
        self.assertLess(wait + budget + 20 + 20, outer)

    def test_admission_subprocess_cap_uses_residue_and_denies_at_deadline(self):
        runtime = self.runtime()
        with patch.object(runtime.time, 'monotonic', return_value=100):
            self.assertEqual(runtime.admission_remaining(160), 20)
            self.assertEqual(runtime.admission_remaining(160, 10), 10)
            self.assertEqual(runtime.admission_remaining(103, 10), 3)
            for deadline in (100, 99):
                with self.assertRaisesRegex(runtime.Denied, '^ADMISSION_SECTION_DEADLINE_EXCEEDED$'):
                    runtime.admission_remaining(deadline)

    def test_quiescence_failure_is_redacted_and_bindings_are_rechecked(self):
        runtime = self.runtime()
        cfg = {'pythonPath': '/python', 'leaseQuiesce': {
            'entrypoint': {'path': '/supervisor.py'},
            'configuration': {'path': '/supervisor.json', 'sha256': 'a'*64}}}
        for error in (runtime.Denied('ADMISSION_OR_DRIVER_FAILED'),
                      subprocess.TimeoutExpired('/private/sentinel', 20)):
            with self.subTest(error=type(error).__name__), \
                    patch.object(runtime, 'verify_files') as verify, \
                    patch.object(runtime, 'capture', side_effect=error) as capture, \
                    self.assertRaisesRegex(runtime.Denied, '^LEASE_QUIESCENCE_UNPROVEN$'):
                runtime.quiesce(cfg)
            self.assertEqual(verify.call_args_list, [call(cfg), call(cfg)])
            capture.assert_called_once_with(['/python', '-I', '-B', '/supervisor.py', '--configuration',
                '/supervisor.json', '--configuration-sha256', 'a'*64, '--quiesce-only'])

    def test_both_operation_modules_are_verified_before_compilation(self):
        runtime = self.runtime()
        auth = (ROOT/'tools/semantic_provider_operation/authorization.py').read_bytes()
        epoch = (ROOT/'tools/semantic_provider_operation/epochs.py').read_bytes()
        cfg = {'authorizationModule': {'path': 'authorization.py', 'sha256': sha(auth)},
               'epochsModule': {'path': 'epochs.py', 'sha256': sha(epoch)}}
        for changed in ('authorization.py', 'epochs.py'):
            files = {'authorization.py': auth, 'epochs.py': epoch}
            files[changed] += b'\nraise AssertionError("UNVERIFIED")\n'
            with self.subTest(changed=changed), patch.object(runtime, 'read', side_effect=lambda p: files[str(p)]), \
                    patch.object(runtime, 'compiled') as compiled, self.assertRaisesRegex(runtime.Denied, 'V52_BOUND_FILE_DRIFT'):
                runtime.operation_modules(cfg)
            compiled.assert_not_called()

    def test_source_pinned_driver_validator_compiles_real_closed_package(self):
        # Lexical POSIX paths let Windows exercise the actual verified-byte
        # bootstrap/validator; custody itself belongs to the native gate.
        from pathlib import PurePosixPath
        class LexicalPath(PurePosixPath):
            def absolute(self): return self
        runtime = self.runtime()
        root = LexicalPath('/source')
        sources = grant_fixture.SourceClosureTests().source_bytes()
        cfg = grant_fixture.part_a.configuration()
        cfg.update(sourceRoot=str(root), sourceHashes={p: sha(raw) for p, raw in sources.items()})
        files = {str(root/p): raw for p, raw in sources.items()}
        stable = encoded(cfg); files['/broker.json'] = stable
        config = {'admissionPath': str(root/grant_fixture.b.ENTRYPOINTS[0]),
            'admissionSha256': cfg['sourceHashes'][grant_fixture.b.ENTRYPOINTS[0]],
            'driverPath': str(root/grant_fixture.b.ENTRYPOINTS[2]),
            'driverSha256': cfg['sourceHashes'][grant_fixture.b.ENTRYPOINTS[2]],
            'admissionConfigurations': {CID: {'path': '/broker.json', 'sha256': sha(stable)}},
            **{key: {'path': str(root/('tools/semantic_provider_operation/'+name+'.py')),
                     'sha256': cfg['sourceHashes']['tools/semantic_provider_operation/'+name+'.py']}
               for key, name in (('authorizationModule', 'authorization'), ('epochsModule', 'epochs'))}}
        original = runtime.compiled
        def compiled(raw, path, name):
            module = original(raw, path, name)
            if name == 'runtime_v52_admission_bootstrap':
                module.private = lambda p: files[str(p)]
                module.private_root = lambda p: None
                module.Path = LexicalPath
            return module
        with patch.dict(sys.modules), patch.object(runtime, 'Path', LexicalPath), \
                patch.object(runtime, 'read', side_effect=lambda p: files[str(p)]), \
                patch.object(runtime, 'compiled', side_effect=compiled):
            if sys.platform != 'linux': sys.modules['fcntl'] = types.ModuleType('fcntl')
            driver, checked = runtime.driver_validator(config, CID)
            self.assertEqual(checked, cfg)
            self.assertEqual(driver.validate(encoded(grant_fixture.grant()))['schema'], driver.SCHEMA)
            self.assertEqual(sys.modules['tools'].__path__, [])
            files[str(root/'tools/semantic_provider_admission_v2/driver_v7.py')] += b'\nraise AssertionError("UNVERIFIED")\n'
            with self.assertRaisesRegex(RuntimeError, 'BROKER_SOURCE_PACKAGE_DRIFT'):
                runtime.driver_validator(config, CID)


class PortableFailedCleanup(unittest.TestCase):
    """Fake runc with real operate dispatch; only Linux custody IO is stubbed."""
    def setUp(self):
        self.r = PortableContracts().runtime()
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.registry = self.root/'registry'; self.base = self.registry/CID
        self.folder = self.base/'epochs/1'; self.runtime_root = self.root/'runc/moby'
        self.config_path = self.root/'runtime.json'; self.original = b'current configuration'
        self.cfg = dict(runtimePath='/runc', pythonPath='/python', runtimeStateRoot=str(self.root/'runc'),
            runtimeSha256='e'*64, registryRoot=str(self.registry), candidates={CID: {}}, admissionPath='/broker',
            admissionConfigurations={CID: dict(path='/admission', sha256='c'*64)}, driverPath='/driver',
            operation=dict(installationRef='installation', entityRef='entity'), opensslBinding={})
        self.record = dict(epoch=1, state='FAILED', bootId='current-boot', runtimeRoot=str(self.runtime_root),
            configurationHash=sha(self.original), driverHash=None, authorizationSha256='a'*64, bundleHash='b'*64,
            generation=None, failure='TWO_PHASE_BROKER_DENIED')
        self.before = copy.deepcopy(self.record)
        self.state = dict(id=CID, bundle=str(self.folder/'bundle'), status='created', pid=42)
        self.files = {str(self.base/'operation.lock'): b'', str(self.config_path): self.original}
        self.calls = []; self.transitions = []; self.closed_locks = []; self.absence = b'container does not exist\n'
        self.probe_code = 1; self.forward_code = 0
        self.fail_phase = None
        self.epochs = types.SimpleNamespace(TERMINAL={'FAILED', 'DELETED', 'ABANDONED'},
            current=lambda *a: self.record, boot_id=lambda: 'current-boot', start_ticks=lambda pid: 123)
        self.quiesce = Mock(); self.validator = Mock()
        self.validator.broker = grant_fixture.b
        self.validator.correlation = grant_fixture.d.correlation
        self.validator.wait_common_lock = lambda *_: contextlib.nullcontext()
        self.validator.components.return_value = (types.SimpleNamespace(record=lambda: {'state': 'PROTECTED'}), None)

    def simulate(self, args, **kw):
        self.calls.append(args)
        if args[:1] == ['/runc'] and args[-2:] == ['state', CID] and 'stdout' in kw:
            raw, error, code = (encoded(self.state), b'', 0) if self.state is not None else (b'', self.absence, self.probe_code)
            kw['stdout'].write(raw)
            if hasattr(kw['stderr'], 'write'):
                kw['stderr'].write(error)
        else:
            code = 1 if args[-1] == self.fail_phase else self.forward_code
            if args[:1] == ['/runc'] and 'delete' in args and code == 0: self.state = None
        return subprocess.CompletedProcess(args, code)

    def run_op(self, mode, *, argv=None, publish_epoch=None):
        # No Linux custody claims are made by these portable tests.
        info = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1, st_dev=1, st_ino=2)
        directory = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0, st_dev=1, st_ino=3)
        native_open, native_close, native_fstat, native_lstat = os.open, os.close, os.fstat, Path.lstat
        lock = self.base/'operation.lock'
        def publish(base, old, value, epochs):
            self.assertEqual(old, self.record); self.record = value; self.transitions.append(value['state'])
        def exclusive(path, raw):
            self.assertNotIn(str(path), self.files); self.files[str(path)] = raw
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(self.r, 'load_configuration', return_value=(self.cfg, self.original)))
            stack.enter_context(patch.object(self.r, 'verify_files'))
            stack.enter_context(patch.object(self.r, 'private_directory'))
            stack.enter_context(patch.object(self.r, 'ancestors'))
            stack.enter_context(patch.object(self.r, 'operation_modules', return_value=(None, self.epochs)))
            stack.enter_context(patch.object(self.r, 'read', side_effect=lambda p, private=True: self.files[str(p)]))
            stack.enter_context(patch.object(self.r, 'exclusive', side_effect=exclusive))
            stack.enter_context(patch.object(self.r, 'publish_epoch', side_effect=publish_epoch or publish))
            stack.enter_context(patch.object(self.r, 'quiesce', self.quiesce))
            stack.enter_context(patch.object(self.r, 'authorization_head', return_value={'sha256': 'a'*64}))
            stack.enter_context(patch.object(self.r, 'driver_validator', return_value=(self.validator,
                getattr(self, 'validator_cfg_for_run', dict(sourceRoot='/source', sourceHashes={})))))
            stack.enter_context(patch.object(self.r.os.path, 'lexists', side_effect=lambda p: str(p) == str(self.base) or str(p) in self.files))
            stack.enter_context(patch.object(self.r.os, 'O_NOFOLLOW', 0, create=True))
            stack.enter_context(patch.object(self.r.os, 'O_NONBLOCK', 0, create=True))
            stack.enter_context(patch.object(self.r.os, 'O_DIRECTORY', 0, create=True))
            stack.enter_context(patch.object(self.r.os, 'open', side_effect=lambda p, *a, **kw: 9999 if p == lock else 9998 if p == self.registry else native_open(p, *a, **kw)))
            stack.enter_context(patch.object(self.r.os, 'close', side_effect=lambda fd: self.closed_locks.append(fd) if fd in (9998, 9999) else native_close(fd)))
            stack.enter_context(patch.object(self.r.os, 'fstat', side_effect=lambda fd: info if fd == 9999 else directory if fd == 9998 else native_fstat(fd)))
            stack.enter_context(patch.object(Path, 'lstat', lambda p, *a, **kw: info if p == lock else directory if p == self.registry else native_lstat(p, *a, **kw)))
            stack.enter_context(patch.object(self.r, 'fcntl', types.SimpleNamespace(flock=Mock(), LOCK_EX=1, LOCK_NB=2)))
            stack.enter_context(patch.object(self.r.subprocess, 'run', side_effect=self.simulate))
            if argv is None:
                argv = ['--root', str(self.runtime_root), mode]
                if mode == 'create': argv += ['--bundle', str(self.root/'oci'/CID)]
                argv += [CID] + (['SIGTERM'] if mode == 'kill' else [])
            return self.r.operate(self.config_path, argv)

    def denied(self, mode, code):
        with self.assertRaisesRegex(self.r.Denied, '^'+code+'$'): self.run_op(mode)

    def consumed(self):
        return dict(schema='ouf.semantic-deployment-consumption.v2', containerId=CID, epoch=1,
            authorizationSha256='a'*64, generation=dict(pid=42, startTicks=123, namespaceInode=456))

    def prepared(self):
        raw = b'sealed driver'; self.record['driverHash'] = sha(raw)
        self.files[str(self.folder/'driver.json')] = raw
        binding = dict(authorizationSha256='a'*64, containerId=CID, epoch=1, configurationHash='c'*64)
        self.validator.validate.return_value = dict(operationBinding=binding, operation={**self.cfg['operation'], 'opensslBinding': {}},
            sourceRoot='/source', sourceHashes={}, profile=dict(bundlePath=str(self.folder/'bundle'), bundleHash='b'*64),
            runtimeBinding=dict(path='/runc', sha256='e'*64, root=str(self.runtime_root)))
        common = {**binding, **self.cfg['operation'], 'driverHash': sha(raw), 'bundleHash': 'b'*64}
        self.files[str(self.folder/'broker-state.json')] = encoded(dict(common,
            schema='ouf.semantic-deployment-broker-journal.v2', state='PROTECTED', runtimeRoot=str(self.runtime_root)))
        self.files[str(self.folder/'deployment.json')] = encoded({**self.consumed(), **common, 'state': 'READY'})
        self.before = copy.deepcopy(self.record)

    def test_unprepared_created_and_stopped_cleanup_and_terminal_preserved(self):
        for status, pid in (('created', 42), ('stopped', 42), ('stopped', 0)):
            with self.subTest(status=status, pid=pid):
                self.state = dict(id=CID, bundle=str(self.folder/'bundle'), status=status, pid=pid)
                self.files.pop(str(self.folder/'runtime-cleanup.json'), None)
                self.assertEqual(self.run_op('state'), 0)
                self.assertEqual(self.run_op('kill'), 0); self.assertEqual(self.run_op('delete'), 0)
                self.assertEqual(self.record, self.before); self.assertEqual(self.transitions, [])
                receipt = json.loads(self.files[str(self.folder/'runtime-cleanup.json')])
                self.assertEqual((receipt['operation'], receipt['runcStatusBefore'], receipt['epoch']), ('delete', status, 1))
        self.quiesce.assert_not_called(); self.validator.validate.assert_not_called()
        self.assertTrue(all(args[0] == '/runc' for args in self.calls))

    def test_running_foreign_id_bundle_root_or_generation_denies_before_forward(self):
        for change in ({'status': 'running'}, {'bundle': str(self.base/'epochs/2/bundle')}, {'id': PEER}):
            for mode in ('state', 'kill', 'delete'):
                with self.subTest(change=change, mode=mode):
                    saved = self.state.copy(); self.state.update(change); self.calls.clear()
                    self.denied(mode, 'FAILED_EPOCH_RUNTIME_STATE_UNPROVEN'); self.assertEqual(len(self.calls), 1)
                    self.state = saved
        self.record['runtimeRoot'] = '/foreign'
        self.denied('delete', 'EPOCH_RUNTIME_ROOT_DRIFT')
        self.record['runtimeRoot'] = str(self.runtime_root)
        consumed = self.consumed(); consumed['generation']['startTicks'] += 1
        self.files[str(self.folder/'deployment.json')] = encoded(consumed)
        self.denied('delete', 'FAILED_EPOCH_GENERATION_UNPROVEN')
        self.assertNotIn(str(self.folder/'runtime-cleanup.json'), self.files)

    def test_consumption_generation_matches_or_pid_is_gone(self):
        self.files[str(self.folder/'deployment.json')] = encoded(self.consumed())
        self.assertEqual(self.run_op('kill'), 0)
        self.epochs.start_ticks = lambda pid: None
        self.assertEqual(self.run_op('delete'), 0)

    def test_old_configuration_is_accepted_but_old_boot_keeps_inactive_protocol(self):
        self.record['configurationHash'] = 'f'*64
        self.assertEqual(self.run_op('kill'), 0); self.assertEqual(self.run_op('delete'), 0)
        self.record['bootId'] = 'old-boot'
        self.state = dict(id=CID, bundle=str(self.folder/'bundle'), status='created', pid=42)
        self.denied('delete', 'RUNTIME_PHASE_INACTIVE_UNEXPECTED_CONTAINER')
        self.denied('kill', 'RUNTIME_PHASE_INACTIVE')

    def test_absent_state_delete_forward_and_receipt_is_idempotent(self):
        self.state = None; self.forward_code = 1
        self.assertEqual(self.run_op('state'), 1)
        self.denied('delete', 'RUNTIME_DELETE_DENIED')
        self.assertNotIn(str(self.folder/'runtime-cleanup.json'), self.files)
        self.forward_code = 0
        self.assertEqual(self.run_op('delete'), 0)
        receipt = self.files[str(self.folder/'runtime-cleanup.json')]
        self.assertEqual(json.loads(receipt)['runcStatusBefore'], 'absent')
        self.assertEqual(self.run_op('delete'), 0)
        self.assertEqual(self.files[str(self.folder/'runtime-cleanup.json')], receipt)
        self.denied('kill', 'RUNTIME_PHASE_INACTIVE')
        for error, code in ((b'permission denied', 1), (b'container does not exist', 2), (b'prefix container does not exist', 1)):
            self.absence, self.probe_code = error, code
            self.denied('delete', 'INACTIVE_RUNTIME_ABSENCE_UNPROVEN')
        self.absence, self.probe_code = b'time="now" level=error msg="container does not exist"\n', 1
        self.assertEqual(self.run_op('delete'), 0)

    def test_unprepared_nonterminal_delete_uses_same_safe_checks_without_quiescence(self):
        self.record.update(state='CREATED', failure=None)
        self.assertEqual(self.run_op('delete'), 0)
        self.assertEqual(self.record['state'], 'DELETED'); self.quiesce.assert_not_called()

    def test_prepared_ordinary_rollback_and_repeated_delete(self):
        self.prepared()
        self.assertEqual(self.run_op('delete'), 0)
        self.assertEqual(self.transitions, ['DELETING', 'FAILED']); self.assertEqual(self.record, self.before)
        self.quiesce.assert_called_once_with(self.cfg)
        phases = [args[-1] for args in self.calls if args[0] == '/python']
        self.assertEqual(phases, ['rollback', 'cleanup'])
        self.assertEqual(self.run_op('delete'), 0)
        self.assertEqual(self.quiesce.call_count, 1)

    def test_prepared_inconsistent_or_partial_rollback_requires_recovery(self):
        self.prepared(); path = str(self.folder/'broker-state.json'); good = self.files[path]
        self.files[path] = good.replace(b'PROTECTED', b'PREPARING')
        self.denied('delete', 'FAILED_PREPARED_EPOCH_REQUIRES_RECOVERY')
        self.assertFalse(any('delete' in args for args in self.calls))
        self.files[path] = good; self.quiesce.side_effect = self.r.Denied('LEASE_QUIESCENCE_UNPROVEN')
        self.denied('delete', 'FAILED_PREPARED_EPOCH_REQUIRES_RECOVERY')
        self.assertEqual(self.record, self.before)
        self.assertNotIn(str(self.folder/'runtime-cleanup.json'), self.files)

    def test_prepared_driver_drift_and_old_configuration_require_recovery(self):
        self.prepared(); driver = str(self.folder/'driver.json'); raw = self.files[driver]
        for change in ('driver', 'configuration', 'preexec'):
            with self.subTest(change=change):
                self.files[driver] = raw; self.record['configurationHash'] = sha(self.original)
                self.validator.components.return_value[0].record = lambda: {'state': 'PROTECTED'}
                if change == 'driver': self.files[driver] += b'drift'
                if change == 'configuration': self.record['configurationHash'] = 'f'*64
                if change == 'preexec': self.validator.components.return_value[0].record = lambda: {'state': 'REMOVED'}
                self.calls.clear()
                self.denied('delete', 'FAILED_PREPARED_EPOCH_REQUIRES_RECOVERY')
                self.assertFalse(any('delete' in args for args in self.calls))
        self.quiesce.assert_not_called()

    def test_runc_delete_failure_is_never_recorded_as_cleanup(self):
        for prepared in (False, True):
            with self.subTest(prepared=prepared):
                if prepared: self.prepared()
                self.forward_code = 1
                self.denied('delete', 'FAILED_PREPARED_EPOCH_REQUIRES_RECOVERY' if prepared else 'RUNTIME_DELETE_DENIED')
                self.assertNotIn(str(self.folder/'runtime-cleanup.json'), self.files)
                self.assertEqual(self.record, self.before)
        self.quiesce.assert_not_called()

    def test_driver_or_broker_failure_requires_recovery_without_receipt(self):
        self.prepared()
        for phase in ('rollback', 'cleanup'):
            with self.subTest(phase=phase):
                self.state = dict(id=CID, bundle=str(self.folder/'bundle'), status='stopped', pid=0)
                self.fail_phase = phase; self.calls.clear()
                self.denied('delete', 'FAILED_PREPARED_EPOCH_REQUIRES_RECOVERY')
                self.assertEqual(self.record, self.before)
                self.assertNotIn(str(self.folder/'runtime-cleanup.json'), self.files)
                if phase == 'rollback': self.assertFalse(any('cleanup' in args for args in self.calls))

    def test_existing_receipt_never_authorizes_a_reappeared_container(self):
        self.assertEqual(self.run_op('delete'), 0)
        self.state = dict(id=CID, bundle=str(self.folder/'bundle'), status='created', pid=42)
        self.denied('kill', 'FAILED_EPOCH_CONTAINER_AFTER_CLEANUP')

    def test_cleanup_exclusive_creation_is_private_and_synced(self):
        runtime = self.r; stream = Mock()
        # Verify the real persistence primitive independently of custody stubs.
        stream.__enter__ = Mock(return_value=stream); stream.__exit__ = Mock(return_value=False)
        with patch.object(runtime.os, 'O_NOFOLLOW', 0, create=True), \
                patch.object(runtime.os, 'open', return_value=99) as opened, \
                patch.object(runtime.os, 'fchmod', create=True) as chmod, \
                patch.object(runtime.os, 'fdopen', return_value=stream), \
                patch.object(runtime.os, 'fsync') as synced, patch.object(runtime.os, 'close'), \
                patch.object(runtime, 'sync_directory') as directory:
            runtime.exclusive(self.folder/'runtime-cleanup.json', b'{}')
        self.assertEqual(opened.call_args.args[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        self.assertEqual(opened.call_args.args[2], 0o600); chmod.assert_called_once_with(99, 0o600)
        synced.assert_called_once_with(99); directory.assert_called_once_with(self.folder)

    def namespace_fixture(self, state='PREPARING'):
        template = dict(commands={'umount': '/umount'}, commandHashes={'umount': 'f'*64}, lockFile='/common.lock')
        self.validator_cfg = dict(containerId=CID, registryRoot=str(self.registry),
            authorities=dict(installationRef='installation', entityRef='entity'),
            preparerTemplate=dict(path='/template.json', sha256=sha(encoded(template))))
        cfg_raw = encoded(self.validator_cfg)
        self.files[str(Path('/admission'))] = cfg_raw
        self.cfg['admissionConfigurations'][CID] = dict(path='/admission', sha256=sha(cfg_raw))
        binding = dict(installationRef='installation', entityRef='entity', containerId=CID, epoch=1,
                       configurationHash=sha(cfg_raw), authorizationSha256='a'*64)
        request = dict(binding=binding, epoch=1, epochRoot=str(self.folder), bundle=str(self.folder/'bundle'),
            runtimeRoot=str(self.runtime_root), template=template, configurationBinding=self.cfg['admissionConfigurations'][CID],
            evidenceBinding=dict(path=str(self.folder/'evidence.json'), sha256='e'*64))
        raw = encoded(request)
        admission = dict(schema='ouf.semantic-admission-journal.v1', transactionId=grant_fixture.d.correlation(binding),
            configurationHash=sha(raw), state=state, driverHash=None, namespaceOwned=True,
            namespaceInode=456, containerGeneration=dict(pid=42, startTicks=123, namespaceInode=456))
        if state == 'FAILED': admission.update(failure='TEMPLATE_DENIED_CODE', namespaceCleanup='OWNED_NAMESPACE_DRIFT')
        self.files[str(self.folder/'admission.json')] = encoded(admission)
        self.files[str(self.folder/'preparer.json')] = raw
        self.files[str(Path('/template.json'))] = encoded(template)
        return dict(namespaceInode=456, namespaceDevice=4, mountId=90)

    def test_owned_residual_namespace_cleanup_before_receipt_and_new_epoch(self):
        for state in ('PREPARING', 'FAILED'):
            with self.subTest(state=state):
                self.calls.clear()
                proof = self.namespace_fixture(state)
                self.state = None
                self.files.pop(str(self.folder/'runtime-netns-cleanup.json'), None)
                with patch.object(self.r, 'executable') as executable, \
                        patch.object(grant_fixture.b, 'owned_namespace_mount', side_effect=[proof, proof, None, None]):
                    # run_op supplies the validator binding, preserving all dispatch.
                    self.validator_cfg_for_run = self.validator_cfg
                    self.assertEqual(self.run_op('delete'), 0)
                    receipt_raw = self.files[str(self.folder/'runtime-netns-cleanup.json')]
                    receipt = json.loads(receipt_raw)
                    self.assertEqual(receipt['mount'], proof)
                    self.assertEqual(receipt['operation'], 'umount')
                    self.assertEqual(self.run_op('delete'), 0)
                    self.assertEqual(self.files[str(self.folder/'runtime-netns-cleanup.json')], receipt_raw)
                self.assertEqual(executable.call_args_list, [call('/umount', 'f'*64)] * 2)
                self.assertEqual(self.record, self.before)
                self.assertEqual([args for args in self.calls if args[0] == '/umount'], [['/umount', str(self.folder/'netns')]])
        # A direct next create recovers the old mount before opening a new epoch.
        proof = self.namespace_fixture()
        self.files.pop(str(self.folder/'runtime-netns-cleanup.json'))
        self.cfg['limits'] = {'maxEpochsPerHour': 10}
        self.epochs.MAX_EPOCH = 10
        self.quiesce.side_effect = self.r.Denied('STOP_AFTER_CLEANUP')
        with patch.object(self.r, 'epoch_inventory', return_value=[]), \
                patch.object(self.r, 'executable'), \
                patch.object(grant_fixture.b, 'owned_namespace_mount', side_effect=[proof, proof, None]):
            self.denied('create', 'STOP_AFTER_CLEANUP')
        self.assertIn(str(self.folder/'runtime-netns-cleanup.json'), self.files)
        self.assertEqual(self.record, self.before)

    def test_owned_namespace_drift_prepared_artifacts_and_umount_failure_fail_closed(self):
        for failure in ('inode', 'driver', 'preexec', 'binding', 'command', 'umount', 'still-mounted'):
            with self.subTest(failure=failure):
                self.calls.clear(); self.files.pop(str(self.folder/'runtime-cleanup.json'), None)
                proof = self.namespace_fixture()
                self.validator_cfg_for_run = self.validator_cfg
                self.state = None
                if failure in ('driver', 'preexec'): self.files[str(self.folder/(failure+'.json'))] = b'{}'
                if failure == 'binding':
                    path = str(self.folder/'admission.json')
                    value = json.loads(self.files[path]); value['configurationHash'] = 'e'*64
                    self.files[path] = encoded(value)
                mounted = grant_fixture.a.OperationDenied('OWNED_NAMESPACE_DRIFT') if failure == 'inode' else \
                    [proof, proof, proof if failure == 'still-mounted' else None]
                self.fail_phase = str(self.folder/'netns') if failure == 'umount' else None
                code = ('OWNED_NAMESPACE_DRIFT' if failure == 'inode' else
                        'FAILED_EPOCH_NAMESPACE_REQUIRES_RECOVERY' if failure in ('driver', 'preexec') else
                        'FAILED_EPOCH_NAMESPACE_BINDING_DRIFT' if failure == 'binding' else
                        'ADAPTER_EXECUTABLE_DRIFT' if failure == 'command' else 'FAILED_EPOCH_NAMESPACE_UNMOUNT_UNPROVEN')
                with patch.object(grant_fixture.b, 'owned_namespace_mount', side_effect=mounted), \
                        patch.object(self.r, 'executable', side_effect=self.r.Denied(code) if failure == 'command' else None), \
                        self.assertRaisesRegex(RuntimeError, '^'+code+'$'):
                    self.run_op('delete')
                if failure not in ('umount', 'still-mounted'):
                    self.assertFalse(any(args[0] == '/umount' for args in self.calls))
                self.assertNotIn(str(self.folder/'runtime-cleanup.json'), self.files)
                self.assertNotIn(str(self.folder/'runtime-netns-cleanup.json'), self.files)
                for name in ('driver.json', 'preexec.json'): self.files.pop(str(self.folder/name), None)

    def test_namespace_cleanup_noop_and_reappeared_mount_is_denied(self):
        proof = self.namespace_fixture()
        self.validator_cfg_for_run = self.validator_cfg
        self.state = None
        with patch.object(self.r, 'executable') as executable, \
                patch.object(grant_fixture.b, 'owned_namespace_mount', return_value=None):
            self.assertEqual(self.run_op('delete'), 0)
            executable.assert_not_called()
        self.assertNotIn(str(self.folder/'runtime-netns-cleanup.json'), self.files)
        path = str(self.folder/'admission.json'); admission = json.loads(self.files[path])
        admission['namespaceOwned'] = False; self.files[path] = encoded(admission)
        with patch.object(grant_fixture.b, 'owned_namespace_mount') as mounted:
            self.assertEqual(self.run_op('delete'), 0)
            mounted.assert_not_called()
        self.namespace_fixture()
        with patch.object(self.r, 'executable'), \
                patch.object(grant_fixture.b, 'owned_namespace_mount', side_effect=[proof, proof, None]):
            self.assertEqual(self.run_op('delete'), 0)
        saved = self.files[str(self.folder/'runtime-netns-cleanup.json')]
        with patch.object(grant_fixture.b, 'owned_namespace_mount', return_value=proof):
            self.denied('delete', 'FAILED_EPOCH_NAMESPACE_RECEIPT_DRIFT')
        self.assertEqual(self.files[str(self.folder/'runtime-netns-cleanup.json')], saved)

    def test_failed_before_runtime_root_or_admission_does_not_block_next_cleanup(self):
        self.record['runtimeRoot'] = None
        # Failed create can precede both runtimeRoot publication and admission.
        self.r.failed_namespace_cleanup(self.cfg, CID, self.runtime_root, self.folder, self.record)

    def test_namespace_cleanup_after_upgrade_uses_historical_bound_template(self):
        proof = self.namespace_fixture()
        old_cfg = copy.deepcopy(self.validator_cfg)
        self.cfg['admissionConfigurations'][CID] = dict(path='/new-admission', sha256='d'*64)
        self.validator_cfg_for_run = dict(preparerTemplate=dict(path='/new-template', sha256='e'*64))
        self.state = None
        with patch.object(grant_fixture.b, 'validate', return_value=old_cfg) as validate, \
                patch.object(grant_fixture.b, 'owned_namespace_mount', side_effect=[proof, proof, None]), \
                patch.object(self.r, 'executable') as executable:
            self.assertEqual(self.run_op('delete'), 0)
        validate.assert_called_once_with(encoded(old_cfg))
        self.assertEqual(executable.call_args_list, [call('/umount', 'f'*64)] * 2)
        self.assertEqual(self.record, self.before)


class PortableAdmissionSection(unittest.TestCase):
    """Real start dispatch/scheduler; virtual time and synthetic child/custody IO."""
    run_op = PortableFailedCleanup.run_op
    denied = PortableFailedCleanup.denied

    def setUp(self):
        PortableFailedCleanup.setUp(self)
        self.record.update(state='CREATED', failure=None)
        self.oci = {'root': {'path': '/synthetic/rootfs'}}
        self.record['bundleHash'] = self.r.digest(self.oci)
        self.files[str(self.folder/'bundle/config.json')] = encoded(self.oci)
        self.driver_raw = b'synthetic sealed driver'
        self.files[str(self.folder/'driver.json')] = self.driver_raw
        binding = dict(authorizationSha256='a'*64, containerId=CID, epoch=1, configurationHash='c'*64)
        self.validator.validate.return_value = dict(operationBinding=binding,
            operation={**self.cfg['operation'], 'opensslBinding': {}}, sourceRoot='/source', sourceHashes={},
            profile=dict(bundlePath=str(self.folder/'bundle'), containerId=CID, bundleHash=self.record['bundleHash']),
            runtimeBinding=dict(path='/runc', sha256='e'*64, root=str(self.runtime_root)))
        self.now = 0
        self.durations = {}
        self.timeouts = []
        self.clock = patch.object(self.r, 'time', types.SimpleNamespace(monotonic=lambda: self.now))
        self.clock.start(); self.addCleanup(self.clock.stop)

    def simulate(self, args, **kw):
        self.calls.append(args)
        phase = args[-1] if '--mode' in args else 'state'
        self.timeouts.append((phase, kw['timeout']))
        self.now += self.durations.get(phase, 0)
        if phase == 'start': self.state['status'] = 'running'
        if phase == 'state': kw['stdout'].write(encoded(self.state))
        return subprocess.CompletedProcess(args, 0)

    def test_previous_started_create_and_start_preserve_history(self):
        # Exercise the real v5.2 create/start and two-file publication protocol.
        # The existing fixture supplies custody, clock and subprocess boundaries.
        self.folder.mkdir(parents=True)
        next_folder = self.folder.with_name('2')
        bundle = self.root/'oci'/CID
        self.cfg['candidates'][CID]['bundleParents'] = [str(bundle.parent)]
        self.cfg['limits'] = {'maxEpochsPerHour': 6}
        self.epochs.MAX_EPOCH = 99
        self.epochs.JOURNAL_SCHEMA = 'fixture'
        self.epochs.validate_journal = lambda raw, cid, number: json.loads(raw)
        self.r.time.time = lambda: 2000
        self.record.update(containerId=CID, state='STARTED', bootId='previous-boot', openedAt=1000,
                           generation={'pid': 42, 'startTicks': 123})
        old = self.record.copy()
        self.files[str(self.folder/'adapter.json')] = encoded(old)
        self.files[str(self.base/'current')] = encoded({'epoch': 1, 'journalSha256': sha(encoded(old))})
        oci = {'root': {'path': str(self.root/'rootfs')}, 'linux': {'namespaces': [{'type': 'network'}]}}
        self.files[str(bundle/'config.json')] = encoded(oci)
        self.files[str(next_folder/'driver.json')] = self.driver_raw
        grant = self.validator.validate.return_value
        grant['operationBinding']['epoch'] = 2
        grant['profile'].update(bundlePath=str(next_folder/'bundle'), bundleHash=self.r.digest(oci))

        def replace(path, old_raw, raw):
            self.assertEqual(self.files[str(path)], old_raw)
            self.files[str(path)] = raw
            if path == self.base/'current':
                pointer = json.loads(raw)
                journal = self.files[str(self.base/'epochs'/str(pointer['epoch'])/'adapter.json')]
                self.assertEqual(pointer['journalSha256'], sha(journal))
                self.record = json.loads(journal)

        self.state = None
        simulate_start = self.simulate
        def simulate(args, **kwargs):
            if args[0] == '/runc' and 'state' in args and self.state is None:
                if hasattr(kwargs['stderr'], 'write'):
                    kwargs['stderr'].write(b'container does not exist')
                return subprocess.CompletedProcess(args, 1)
            if args[0] == '/runc' and 'create' in args:
                self.state = dict(id=CID, bundle=str(next_folder/'bundle'), status='created', pid=42)
                return subprocess.CompletedProcess(args, 0)
            return simulate_start(args, **kwargs)

        self.simulate = simulate
        publish = self.r.publish_epoch
        with patch.object(self.r, 'replace_cas', side_effect=replace), patch.object(self.r, 'sync_directory'):
            self.assertEqual(self.run_op('create', publish_epoch=publish), 0)
            self.assertEqual(self.run_op('start', publish_epoch=publish), 0)
        self.assertEqual(json.loads(self.files[str(self.folder/'adapter.json')]), {**old, 'state': 'ABANDONED'})
        self.assertEqual((self.record['state'], self.record['epoch']), ('STARTED', 2))
        self.assertEqual(self.record['bootId'], self.epochs.boot_id())

    def test_start_keeps_revalidations_and_existing_child_caps(self):
        self.durations = {'prepare': 17, 'hook': 2, 'start': 2}
        self.assertEqual(self.run_op('start'), 0)
        self.assertEqual(self.record['state'], 'STARTED')
        self.assertEqual(self.timeouts, [('state', 20), ('cohort-ready', 20), ('state', 20),
                                        ('prepare', 20), ('hook', 10), ('start', 20), ('state', 20)])
        self.assertEqual(self.closed_locks, [9998, 9999])

    def overrun(self, phase, absent=None):
        # Deliberately unhealthy boundary returning after its allotted time.
        self.durations = {phase: self.r.ADMISSION_SECTION_BUDGET_SECONDS + 1}
        self.denied('start', 'ADMISSION_SECTION_DEADLINE_EXCEEDED')
        self.assertEqual(self.record['state'], 'FAILED')
        self.assertEqual(self.record['failure'], 'ADMISSION_SECTION_DEADLINE_EXCEEDED')
        if absent:
            self.assertFalse(any('--mode' in args and args[-1] == absent for args in self.calls))
        self.assertEqual(self.closed_locks, [9998, 9999])

    def test_expired_state_denies_prepare_and_releases_lock(self):
        self.overrun('state', 'prepare')

    def test_expired_prepare_denies_hook_and_releases_lock(self):
        self.overrun('prepare', 'hook')

    def test_expired_hook_denies_start_and_releases_lock(self):
        self.overrun('hook', 'start')

    def test_expired_start_denies_running_readback_and_releases_lock(self):
        self.overrun('start')
        self.assertEqual(sum(phase == 'state' for phase, _ in self.timeouts), 2)

    def test_late_start_is_capped_to_remaining_section(self):
        # Full legal prepare plus local validation leaves less than the old cap.
        self.durations = {'prepare': 20}
        grant = self.validator.validate.return_value
        def validate(raw):
            self.now += 25
            return grant
        self.validator.validate.side_effect = validate
        self.assertEqual(self.run_op('start'), 0)
        self.assertIn(('hook', 10), self.timeouts)
        self.assertIn(('start', 15), self.timeouts)
        self.assertIn(('state', 15), self.timeouts)

    def test_expired_driver_validation_denies_hook_and_releases_lock(self):
        grant = self.validator.validate.return_value
        def validate(raw):
            self.now += self.r.ADMISSION_SECTION_BUDGET_SECONDS
            return grant
        self.validator.validate.side_effect = validate
        self.denied('start', 'ADMISSION_SECTION_DEADLINE_EXCEEDED')
        self.assertFalse(any('--mode' in args and args[-1] == 'hook' for args in self.calls))
        self.assertEqual(self.record['state'], 'FAILED')
        self.assertEqual(self.closed_locks, [9998, 9999])

    def test_expired_generation_read_denies_started_and_releases_lock(self):
        def ticks(pid):
            self.now += self.r.ADMISSION_SECTION_BUDGET_SECONDS
            return 123
        self.epochs.start_ticks = ticks
        self.denied('start', 'ADMISSION_SECTION_DEADLINE_EXCEEDED')
        self.assertNotIn('STARTED', self.transitions)
        self.assertEqual(self.record['failure'], 'ADMISSION_SECTION_DEADLINE_EXCEEDED')
        self.assertEqual(self.closed_locks, [9998, 9999])

    def test_subprocess_timeout_at_section_deadline_uses_section_code(self):
        original = self.simulate
        def simulate(args, **kw):
            if args[-1] == 'prepare':
                self.now = self.r.ADMISSION_SECTION_BUDGET_SECONDS
                raise subprocess.TimeoutExpired('synthetic', kw['timeout'])
            return original(args, **kw)
        self.simulate = simulate
        self.denied('start', 'ADMISSION_SECTION_DEADLINE_EXCEEDED')
        self.assertEqual(self.record['failure'], 'ADMISSION_SECTION_DEADLINE_EXCEEDED')
        self.assertEqual(self.closed_locks, [9998, 9999])

    def test_early_child_timeout_keeps_existing_redaction(self):
        original = self.simulate
        def simulate(args, **kw):
            if args[-1] == 'prepare':
                self.now = 20
                raise subprocess.TimeoutExpired('synthetic', kw['timeout'])
            return original(args, **kw)
        self.simulate = simulate
        self.denied('start', 'DOCKER_RUNTIME_OPERATION_UNPROVEN')
        self.assertEqual(self.closed_locks, [9998, 9999])


class NativeEpochs(operation_fixture.Fixture):
    __unittest_skip__ = not NATIVE
    __unittest_skip_why__ = 'set OUF_RUNTIME_V52_NATIVE=1 under native Linux root'

    def setUp(self):
        super().setUp()
        self.source = self.root/'runtime_v52.py'; self.write(self.source, SOURCE.read_bytes())
        self.r = load(self.source, 'runtime_v52_native')
        self.registry = self.root/'registry'; self.registry.mkdir(mode=0o700)
        for cid in (CID, PEER):
            folder = self.registry/cid; folder.mkdir(mode=0o700)
            (folder/'epochs').mkdir(mode=0o700); self.write(folder/'operation.lock', b'lock')
        self.bundle_parent = self.root/'bundles'; self.bundle_parent.mkdir(mode=0o700)
        self.bundle = self.bundle_parent/CID; self.bundle.mkdir(mode=0o700)
        (self.bundle/'rootfs').mkdir(mode=0o700)
        self.oci = {'root': {'path': 'rootfs'}, 'linux': {'namespaces': [{'type': 'network'}]},
                    'hooks': {'prestart': []}}
        self.write(self.bundle/'config.json', encoded(self.oci))
        self.runtime = self.root/'runc'; self.write(self.runtime, b'#!/bin/sh\nexit 99\n', 0o700)
        self.broker = self.root/'broker.py'; self.write(self.broker, b'# fake broker\n')
        self.driver = self.root/'hook.py'; self.write(self.driver, b'# fake hook\n')
        self.quiescer = self.root/'quiesce.py'; self.write(self.quiescer, b'# fake revocation\n')
        self.qcfg = self.root/'quiesce.json'; self.write(self.qcfg, b'{}')
        self.auth_module = self.root/'authorization.py'
        self.epoch_module = self.root/'epochs.py'
        self.mandates_module = self.root/'mandates.py'
        for source, destination in ((ROOT/'tools/semantic_provider_operation/authorization.py', self.auth_module),
                (ROOT/'tools/semantic_provider_operation/epochs.py', self.epoch_module),
                (ROOT/'tools/semantic_authority_mandates/mandates.py', self.mandates_module)):
            self.write(destination, source.read_bytes())
        self.admissions = {}
        self.broker_cfg = {'sourceRoot': str(self.root), 'sourceHashes': {k: 'c'*64 for k in grant_fixture.b.SOURCES}}
        for cid in (CID, PEER):
            path = self.root/(cid+'.broker.json'); self.write(path, encoded(self.broker_cfg))
            self.admissions[cid] = self.pin(path)
        self.python = Path(sys.executable).resolve(strict=True)
        self.cfg = {'schema': self.r.SCHEMA, 'sourceHash': sha(self.source.read_bytes()),
            'runtimePath': str(self.runtime), 'runtimeSha256': sha(self.runtime.read_bytes()),
            'pythonPath': str(self.python), 'pythonSha256': sha(self.python.read_bytes()),
            'driverPath': str(self.driver), 'driverSha256': sha(self.driver.read_bytes()),
            'admissionPath': str(self.broker), 'admissionSha256': sha(self.broker.read_bytes()),
            'registryRoot': str(self.registry), 'runtimeStateRoot': str(self.root/'state'), 'opensslBinding': self.ssl,
            'candidates': {cid: {'role': role, 'bundleParents': [str(self.bundle_parent)]}
                           for cid, role in ((CID, 'adapter'), (PEER, 'southbound'))},
            'admissionConfigurations': self.admissions,
            'authorizationModule': self.pin(self.auth_module), 'epochsModule': self.pin(self.epoch_module),
            'operation': {'authorizationRoot': str(self.chain), 'anchorBinding': self.anchor,
                'mandateRoot': str(self.ledger_root), 'mandatesModule': self.pin(self.mandates_module),
                'installationRef': 'inst', 'entityRef': 'ent', 'issuerRef': 'installer'},
            'leaseQuiesce': {'entrypoint': self.pin(self.quiescer), 'configuration': self.pin(self.qcfg)},
            'limits': {'maxEpochsPerHour': 6}}
        self.configuration = self.root/'runtime.json'; self.write(self.configuration, encoded(self.cfg))
        self.authorize()
        self.process = subprocess.Popen([str(self.python), '-I', '-B', '-c', 'import time; time.sleep(120)'],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop_process)
        self.exists, self.running = False, False
        self.quiesce_ok, self.broker_ok, self.driver_ok, self.create_ok = True, True, True, True
        self.state_ok, self.kill_ok, self.delete_ok = True, True, True
        self.grant_change = lambda grant: None
        self.calls = []; self.native_run = subprocess.run

    def stop_process(self):
        if self.process.poll() is None:
            self.process.terminate(); self.process.wait(timeout=5)

    def pin(self, path): return {'path': str(path), 'sha256': sha(path.read_bytes())}

    def authorize(self, sequence=1, decision='OPERATE', **changes):
        previous = sha((self.chain/(str(sequence-1)+'.json')).read_bytes()) if sequence > 1 else None
        value = json.loads(self.payload(sequence, previous, 1400+sequence, decision))
        value['runtimeConfigurationSha256'] = sha(self.configuration.read_bytes())
        for cid, role in ((CID, 'adapter'), (PEER, 'southbound')):
            value['roles'][role]['admissionConfigurationSha256'] = self.admissions[cid]['sha256']
        value.update(changes)
        self.operation_raw = self.put(sequence, encoded(value))

    def args(self, mode):
        result = ['--root', str(self.root/'state/moby'), mode]
        if mode == 'create': result += ['--bundle', str(self.bundle)]
        if mode == 'delete': result += ['--force']
        result += [CID]
        if mode == 'kill': result += ['SIGTERM']
        return result

    def row(self): return self.e.current(self.registry, CID)

    def folder(self): return self.registry/CID/'epochs'/str(self.row()['epoch'])

    def hook_state(self):
        return {'id': CID, 'bundle': str(self.folder()/'bundle'), 'status': 'running' if self.running else 'created',
                'pid': self.process.pid}

    def prepare_grant(self):
        row = self.row(); root = self.folder(); grant = grant_fixture.grant()
        binding = {'authorizationSha256': row['authorizationSha256'], 'containerId': CID,
                   'epoch': row['epoch'], 'configurationHash': self.admissions[CID]['sha256']}
        grant.update(sourceRoot=self.broker_cfg['sourceRoot'], sourceHashes=self.broker_cfg['sourceHashes'],
            operationBinding=binding, operation={**self.cfg['operation'], 'opensslBinding': self.ssl},
            consumptionJournal=str(root/'deployment.json'), preexecJournal=str(root/'preexec.json'),
            evidenceBinding={'path': str(root/'evidence.json'), 'sha256': 'c'*64},
            runtimeBinding={**self.pin(self.runtime), 'root': str(self.root/'state/moby')})
        grant['profile'].update(containerId=CID, bundlePath=str(root/'bundle'), bundleHash=row['bundleHash'],
            transactionId=grant_fixture.d.correlation(binding), namespacePath=str(root/'netns'))
        self.grant_change(grant)
        self.write(root/'driver.json', encoded(grant))

    def simulate(self, argv, **kw):
        if argv[0] == str(self.openssl): return self.native_run(argv, **kw)
        self.calls.append((list(argv), dict(kw)))
        self.assertEqual(kw['env'], self.r.ENV)
        code, output, error = 0, b'', b''
        if str(self.quiescer) in argv:
            row = self.row()
            if row and row['state'] == 'DELETING':
                self.assertFalse(self.exists); self.assertFalse(self.running)
            self.assertEqual(argv, [str(self.python), '-I', '-B', str(self.quiescer), '--configuration', str(self.qcfg),
                '--configuration-sha256', self.cfg['leaseQuiesce']['configuration']['sha256'], '--quiesce-only'])
            self.assertEqual(kw['stdin'], subprocess.DEVNULL); self.assertNotIn('input', kw)
            self.assertEqual(kw['timeout'], 20)
            code = 0 if self.quiesce_ok else 1
        elif str(self.broker) in argv:
            mode = argv[-1]; row = self.row()
            self.assertEqual(argv, [str(self.python), '-I', '-B', str(self.broker), '--configuration',
                self.admissions[CID]['path'], '--container-id', CID, '--bundle', str(self.folder()/'bundle'),
                '--runtime-root', str(self.root/'state/moby'), '--epoch', str(row['epoch']), '--mode', mode])
            self.assertEqual(kw['timeout'], 20)
            if mode == 'cleanup':
                self.assertEqual(row['state'], 'DELETING')
                self.assertEqual(kw['stdin'], subprocess.DEVNULL); self.assertNotIn('input', kw)
            else:
                self.assertNotIn('stdin', kw)
                expected = {'id': CID, 'bundleHash': self.r.digest(self.shadow_oci())} if mode == 'authorize-create' else self.hook_state()
                self.assertEqual(kw['input'], encoded(expected))
                self.assertEqual(row['state'], {'authorize-create': 'OPENING', 'record-created': 'CREATING',
                    'cohort-ready': 'CREATED', 'prepare': 'PREPARING'}[mode])
            if mode == 'prepare': self.prepare_grant()
            code = 0 if self.broker_ok else 1
        elif str(self.driver) in argv:
            mode = argv[-1]
            self.assertEqual(argv, [str(self.python), '-I', '-B', str(self.driver), '--configuration',
                str(self.folder()/'driver.json'), '--mode', mode])
            self.assertEqual(kw['timeout'], 10 if mode == 'hook' else 20)
            if mode == 'hook':
                self.assertEqual(kw['input'], encoded(self.hook_state())); self.assertNotIn('stdin', kw)
            else:
                self.assertEqual(kw['stdin'], subprocess.DEVNULL); self.assertNotIn('input', kw)
            if mode == 'start': self.running = True
            code = 0 if self.driver_ok else 1
        elif argv[0] == str(self.runtime):
            if 'state' in argv:
                if not self.state_ok: code = 2
                elif self.exists: output = encoded(self.hook_state())
                else: code, error = 1, b'container does not exist\n'
            elif 'create' in argv:
                self.assertEqual(argv, [str(self.runtime), '--root', str(self.root/'state/moby'), 'create',
                    '--bundle', str(self.folder()/'bundle'), CID])
                self.assertEqual(kw['timeout'], 40); self.assertNotIn('stderr', kw)
                self.exists = self.create_ok; code = 0 if self.create_ok else 1
            elif 'delete' in argv:
                row = self.row()  # absent or terminal epochs take the inactive protocol
                if row is not None and row['state'] not in self.e.TERMINAL:
                    self.assertEqual(row['state'], 'DELETING')
                if self.delete_ok: self.exists, self.running = False, False
                else: code = 1
            elif 'kill' in argv: code = 0 if self.kill_ok else 1
            else: self.fail('unexpected runc operation')
        else: self.fail('unexpected subprocess')
        if hasattr(kw.get('stdout'), 'write'): kw['stdout'].write(output)
        if hasattr(kw.get('stderr'), 'write'): kw['stderr'].write(error)
        return subprocess.CompletedProcess(argv, code)

    def shadow_oci(self):
        return {**self.oci, 'root': {'path': str(self.bundle/'rootfs')}}

    def run_op(self, mode):
        with patch.object(self.r.subprocess, 'run', side_effect=self.simulate), \
                patch.object(self.r, 'driver_validator', return_value=(grant_fixture.d, self.broker_cfg)):
            return self.r.operate(self.configuration, self.args(mode))

    def denied(self, mode, code):
        with self.assertRaisesRegex(self.r.Denied, '^'+code+'$'): self.run_op(mode)

    def seed(self, number=1, state='DELETED', **changes):
        root = self.registry/CID/'epochs'/str(number); root.mkdir(mode=0o700)
        row = {'schema': self.e.JOURNAL_SCHEMA, 'containerId': CID, 'epoch': number, 'bootId': self.e.boot_id(),
            'authorizationSha256': sha(self.operation_raw), 'configurationHash': sha(self.configuration.read_bytes()),
            'state': state, 'runtimeRoot': str(self.root/'state/moby'), 'bundleHash': None, 'driverHash': None,
            'generation': None, 'openedAt': int(time.time()), 'failure': None}
        row.update(changes); raw = encoded(row)
        self.write(root/'adapter.json', raw)
        self.write(self.registry/CID/'current', encoded({'epoch': number, 'journalSha256': sha(raw)}))

    def test_two_full_cycles_same_authorization(self):
        for epoch in (1, 2):
            self.assertEqual(self.run_op('create'), 0); self.assertEqual(self.row()['state'], 'CREATED')
            self.assertEqual(self.row()['epoch'], epoch)
            self.assertEqual(self.run_op('start'), 0); row = self.row()
            self.assertEqual(row['state'], 'STARTED')
            self.assertEqual(row['authorizationSha256'], sha(self.operation_raw))
            self.assertEqual(row['generation'], {'pid': self.process.pid, 'startTicks': self.e.start_ticks(self.process.pid)})
            self.assertEqual(self.run_op('state'), 0); self.assertEqual(self.run_op('kill'), 0)
            self.assertEqual(self.run_op('delete'), 0); self.assertEqual(self.row()['state'], 'DELETED')
        self.assertEqual(sum(str(self.quiescer) in argv for argv, _ in self.calls), 4)
        for path in (self.registry/CID/'current', self.folder()/'adapter.json', self.folder()/'bundle/config.json'):
            info = path.stat(); self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0, 0, 0o600))
        self.assertEqual(stat.S_IMODE(self.folder().stat().st_mode), 0o700)

    def test_old_boot_abandoned_without_rollback(self):
        self.seed(state='CREATED', bootId='6dc087ac-1111-4222-8333-444455556666')
        self.run_op('create')
        self.assertEqual(json.loads((self.registry/CID/'epochs/1/adapter.json').read_bytes())['state'], 'ABANDONED')
        self.assertEqual(self.row()['epoch'], 2)
        self.assertFalse(any(str(self.driver) in argv for argv, _ in self.calls))

    def test_previous_started_history_survives_new_start(self):
        self.seed(state='STARTED', bootId='6dc087ac-1111-4222-8333-444455556666',
                  generation={'pid': 42, 'startTicks': 123})
        old = self.row()
        self.run_op('create')
        self.run_op('start')
        retained = json.loads((self.registry/CID/'epochs/1/adapter.json').read_bytes())
        self.assertEqual(retained, {**old, 'state': 'ABANDONED'})
        self.assertEqual((self.row()['state'], self.row()['epoch']), ('STARTED', 2))

    def test_old_boot_existing_runc_is_not_abandoned(self):
        self.seed(state='CREATED', bootId='6dc087ac-1111-4222-8333-444455556666'); self.exists = True
        self.denied('create', 'RUNTIME_PHASE_INACTIVE_UNEXPECTED_CONTAINER')
        self.assertEqual(self.row()['state'], 'CREATED')

    def test_same_boot_open_is_never_changed(self):
        self.run_op('create'); before = (self.folder()/'adapter.json').read_bytes()
        self.denied('create', 'EPOCH_STILL_OPEN')
        self.assertEqual((self.folder()/'adapter.json').read_bytes(), before)

    def test_six_recent_epochs_deny_and_old_epochs_do_not_count(self):
        for number in range(1, 7): self.seed(number)
        self.denied('create', 'EPOCH_RATE_EXCEEDED'); self.assertEqual(self.row()['epoch'], 6)
        self.assertEqual(self.calls, [])
        path = self.registry/CID/'epochs/1/adapter.json'; row = json.loads(path.read_bytes())
        self.write(path, encoded({**row, 'openedAt': int(time.time())-3601}))
        self.run_op('create'); self.assertEqual(self.row()['epoch'], 7)

    def test_quiescence_failure_opens_nothing(self):
        self.quiesce_ok = False; self.denied('create', 'LEASE_QUIESCENCE_UNPROVEN')
        self.assertIsNone(self.row()); self.assertEqual(list((self.registry/CID/'epochs').iterdir()), [])

    def test_stop_and_configuration_hash_deny_before_opening(self):
        self.authorize(2, 'STOP'); self.denied('create', 'OPERATION_NOT_OPERATE')
        self.authorize(3, runtimeConfigurationSha256='f'*64)
        self.denied('create', 'OPERATION_RUNTIME_CONFIGURATION_DRIFT'); self.assertIsNone(self.row())

    def test_revoked_authorization_denies(self):
        self.append([{'keyRef': 'key-a', 'notBefore': 1900, 'expiresAt': 1900+60*operation_fixture.DAY, 'state': 'REVOKED'}])
        self.denied('create', 'OPERATION_KEY_REVOKED'); self.assertIsNone(self.row())

    def test_admission_hash_and_wrong_role_deny(self):
        value = json.loads(self.operation_raw); value['roles']['adapter']['admissionConfigurationSha256'] = 'f'*64
        self.put(1, encoded(value)); self.denied('create', 'OPERATION_ADMISSION_CONFIGURATION_DRIFT')
        value['roles']['adapter']['admissionConfigurationSha256'] = self.admissions[CID]['sha256']
        value['roles']['adapter']['containerId'], value['roles']['southbound']['containerId'] = PEER, CID
        self.put(1, encoded(value)); self.denied('create', 'OPERATION_ADMISSION_CONFIGURATION_DRIFT')

    def test_start_rechecks_stop_and_head_replacement(self):
        self.run_op('create'); self.authorize(2, 'STOP'); self.denied('start', 'OPERATION_NOT_OPERATE')
        self.assertEqual(self.row()['state'], 'FAILED')
        self.exists = False; self.authorize(3); self.run_op('create'); self.authorize(4)
        self.denied('start', 'EPOCH_AUTHORIZATION_DRIFT'); self.assertEqual(self.row()['state'], 'FAILED')

    def test_denied_first_start_docker_cleanup_then_epoch_two(self):
        self.run_op('create'); self.broker_ok = False
        self.denied('start', 'TWO_PHASE_BROKER_DENIED')
        self.assertIsNone(self.row()['driverHash']); before = (self.folder()/'adapter.json').read_bytes()
        calls = len(self.calls)
        self.assertEqual(self.run_op('kill'), 0); self.assertEqual(self.run_op('delete'), 0)
        self.assertEqual((self.folder()/'adapter.json').read_bytes(), before)
        self.assertEqual(stat.S_IMODE((self.folder()/'runtime-cleanup.json').stat().st_mode), 0o600)
        self.assertFalse(any(str(self.quiescer) in argv or str(self.broker) in argv or str(self.driver) in argv
                             for argv, _ in self.calls[calls:]))
        self.broker_ok = True
        self.assertEqual(self.run_op('create'), 0); self.assertEqual(self.row()['epoch'], 2)
        self.assertEqual(self.run_op('start'), 0); self.assertEqual(self.row()['state'], 'STARTED')

    def test_broker_error_after_opening_is_failed(self):
        self.broker_ok = False; self.denied('create', 'TWO_PHASE_BROKER_DENIED')
        self.assertEqual((self.row()['state'], self.row()['failure']), ('FAILED', 'TWO_PHASE_BROKER_DENIED'))
        self.assertEqual(len(list((self.registry/CID/'epochs').iterdir())), 1)

    def test_legacy_grant_denied(self):
        self.run_op('create'); self.grant_change = lambda g: g.update(schema='ouf.semantic-preexec-driver.v6')
        self.denied('start', 'EXACT_DRIVER_CONFIGURATION_REQUIRED'); self.assertEqual(self.row()['state'], 'FAILED')
        self.assertFalse(any(str(self.driver) in argv for argv, _ in self.calls))

    def test_epoch_authorization_and_configuration_grant_bindings(self):
        for key, bad in (('epoch', 999), ('authorizationSha256', 'f'*64), ('configurationHash', 'e'*64)):
            with self.subTest(key=key):
                self.exists = False; self.run_op('create')
                def tamper(g, key=key, bad=bad):
                    g['operationBinding'][key] = bad
                    g['profile']['transactionId'] = grant_fixture.d.correlation(g['operationBinding'])
                    if key == 'epoch':
                        root = self.registry/CID/'epochs/999'
                        g.update(consumptionJournal=str(root/'deployment.json'), preexecJournal=str(root/'preexec.json'))
                        g['evidenceBinding']['path'] = str(root/'evidence.json'); g['profile']['bundlePath'] = str(root/'bundle')
                self.grant_change = tamper
                self.denied('start', 'DRIVER_OPERATION_BINDING_DRIFT'); self.assertEqual(self.row()['state'], 'FAILED')
                self.grant_change = lambda g: None

    def test_driver_or_create_failure_marks_failed_without_replay(self):
        self.create_ok = False; self.denied('create', 'RUNTIME_CREATE_DENIED')
        self.assertEqual(self.row()['state'], 'FAILED')
        self.create_ok = True; self.run_op('create'); self.driver_ok = False
        self.denied('start', 'OCI_ADMISSION_GATE_DENIED'); self.assertEqual(self.row()['state'], 'FAILED')

    def test_live_state_and_kill_errors_record_failed(self):
        for mode, flag, code in (('state', 'state_ok', 'RUNTIME_STATE_DENIED'), ('kill', 'kill_ok', 'RUNTIME_KILL_DENIED')):
            with self.subTest(mode=mode):
                self.exists = False; self.run_op('create'); setattr(self, flag, False)
                self.denied(mode, code); self.assertEqual(self.row()['failure'], code)
                setattr(self, flag, True)

    def test_delete_failure_does_not_rollback_live_generation(self):
        self.run_op('create'); self.run_op('start'); before = len(self.calls); self.delete_ok = False
        self.denied('delete', 'RUNTIME_DELETE_DENIED')
        self.assertEqual(self.row()['state'], 'FAILED')
        self.assertFalse(any(str(self.driver) in argv for argv, _ in self.calls[before:]))
        self.assertFalse(any(str(self.quiescer) in argv for argv, _ in self.calls[before:]))

    def test_delete_quiesces_after_runc_before_rollback_and_cleanup(self):
        self.run_op('create'); self.run_op('start'); before = len(self.calls)
        generation = self.row()['generation']
        with patch.object(self.r, 'publish_epoch', wraps=self.r.publish_epoch) as publish:
            self.assertEqual(self.run_op('delete'), 0)
        self.assertEqual([call.args[2]['state'] for call in publish.call_args_list], ['DELETING', 'DELETED'])
        calls = [argv for argv, _ in self.calls[before:]]
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[0], [str(self.runtime), *self.args('delete')])
        self.assertIn(str(self.quiescer), calls[1]); self.assertEqual(calls[1][-1], '--quiesce-only')
        self.assertIn(str(self.driver), calls[2]); self.assertEqual(calls[2][-2:], ['--mode', 'rollback'])
        self.assertIn(str(self.broker), calls[3]); self.assertEqual(calls[3][-2:], ['--mode', 'cleanup'])
        self.assertEqual((self.row()['state'], self.row()['failure']), ('DELETED', None))
        self.assertEqual(self.row()['generation'], generation)

    def test_delete_quiescence_failure_marks_failed_without_rollback_or_cleanup(self):
        self.run_op('create'); self.run_op('start'); before = len(self.calls)
        generation = self.row()['generation']; self.quiesce_ok = False
        with patch.object(self.r, 'publish_epoch', wraps=self.r.publish_epoch) as publish:
            self.denied('delete', 'LEASE_QUIESCENCE_UNPROVEN')
        self.assertEqual([call.args[2]['state'] for call in publish.call_args_list], ['DELETING', 'FAILED'])
        self.assertEqual((self.row()['state'], self.row()['failure']), ('FAILED', 'LEASE_QUIESCENCE_UNPROVEN'))
        self.assertEqual(self.row()['generation'], generation)
        self.assertFalse(self.exists)
        calls = [argv for argv, _ in self.calls[before:]]
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], [str(self.runtime), *self.args('delete')])
        self.assertIn(str(self.quiescer), calls[1])
        self.assertFalse(any(str(self.driver) in argv or str(self.broker) in argv for argv in calls))

    def test_failed_cas_does_not_overwrite_journal(self):
        self.run_op('create'); old = self.row(); path = self.folder()/'adapter.json'; before = path.read_bytes()
        self.write(self.registry/CID/'current', encoded({'epoch': 1, 'journalSha256': 'f'*64}))
        with self.assertRaisesRegex(self.r.Denied, 'EPOCH_CAS_DRIFT'):
            self.r.publish_epoch(self.registry/CID, old, {**old, 'state': 'FAILED', 'failure': 'TEST_FAILURE'}, self.e)
        self.assertEqual(path.read_bytes(), before)

    def test_error_with_cas_failure_preserves_foreign_change(self):
        original_publish = self.r.publish_epoch
        def fail(base, old, value, epochs):
            if value['state'] == 'FAILED': raise self.r.Denied('EPOCH_CAS_DRIFT')
            return original_publish(base, old, value, epochs)
        self.broker_ok = False
        with patch.object(self.r, 'publish_epoch', side_effect=fail):
            self.denied('create', 'TWO_PHASE_BROKER_DENIED')
        self.assertEqual(self.row()['state'], 'OPENING')

    def test_terminal_and_absent_state_delete_use_inactive_protocol(self):
        self.assertEqual(self.run_op('state'), 1); self.assertEqual(self.run_op('delete'), 0)
        self.seed(); self.assertEqual(self.run_op('state'), 1); self.assertEqual(self.run_op('delete'), 0)
        self.assertFalse(any(str(self.broker) in argv or str(self.driver) in argv for argv, _ in self.calls))
        self.exists = True; self.denied('delete', 'RUNTIME_PHASE_INACTIVE_UNEXPECTED_CONTAINER')

    def test_configuration_and_bound_byte_custody(self):
        self.assertEqual(self.r.load_configuration(self.configuration)[0], self.cfg)
        for change in (lambda c: c.update(armingRoot='/bad'), lambda c: c['limits'].update(maxEpochsPerHour=True),
                       lambda c: c['candidates'][PEER].update(role='adapter')):
            bad = copy.deepcopy(self.cfg); change(bad); self.write(self.configuration, encoded(bad))
            with self.assertRaises(self.r.Denied): self.r.load_configuration(self.configuration)
        self.write(self.configuration, encoded(self.cfg)+b'\n')
        with self.assertRaises(self.r.Denied): self.r.load_configuration(self.configuration)
        self.write(self.configuration, encoded(self.cfg)); self.configuration.chmod(0o644)
        with self.assertRaises(self.r.Denied): self.r.load_configuration(self.configuration)
        self.configuration.chmod(0o600)
        self.write(self.epoch_module, self.epoch_module.read_bytes()+b'\nraise AssertionError()\n')
        self.denied('create', 'V52_BOUND_FILE_DRIFT')


if __name__ == '__main__': unittest.main()
