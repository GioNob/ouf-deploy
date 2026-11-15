"""v5.2 native custody/authorization with simulated OCI subprocess boundaries.

Only ephemeral test authorization signatures are produced. No Docker, network,
nft, installed configuration or production key is used.
"""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import types
import unittest
from unittest.mock import call, patch

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
                self.assertEqual(self.row()['state'], 'DELETING')
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
