"""R3 installation contracts and Linux/root CLI scenarios on the real 41a fixture."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from tools.semantic_provider_r3 import install_common as I
import test_semantic_provider_r3_integration as F

A, C, ROOT, V = I.A, I.C, I.ROOT, I.V
execution_fixture = F.admission_fixture.part_a
NATIVE = os.environ.get("OUF_R3_INSTALL_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_R3_INSTALL_NATIVE requires Linux root:root; refusing to skip")


DOCKER = r'''
import json,pathlib,sys
base=pathlib.Path(BASE); args=sys.argv[1:]
with (base/'docker.jsonl').open('a') as stream: stream.write(json.dumps(args)+'\n')
assert args[:3]==['--host','unix:///fixture/docker.sock','inspect'] and len(args)==4
print(json.dumps([json.loads((base/'docker-state.json').read_bytes())[args[3]]]))
'''

SYSTEMCTL = r'''
import json,pathlib,shlex,sys
base=pathlib.Path(BASE); args=sys.argv[1:]; unit='ouf-semantic-lease-supervisor-v2.service'
with (base/'systemctl.jsonl').open('a') as stream: stream.write(json.dumps(args)+'\n')
state=base/'unit-active'
unitpath=pathlib.Path('/etc/systemd/system')/unit
loaded=base/'unit-load-state'
if args==['daemon-reload']: loaded.write_text('loaded' if unitpath.exists() else 'not-found')
elif args==['enable','--now',unit]:
    if (base/'enable-fail').exists(): raise SystemExit(1)
    state.write_text('active')
    command=shlex.split(next(line for line in unitpath.read_text().splitlines() if line.startswith('ExecStart=')).split('=',1)[1])
    cfg=json.loads(pathlib.Path(command[command.index('--configuration')+1]).read_bytes())
    status={'schema':'ouf.semantic-provider-lease-supervisor-status.v1','state':'WAITING',
        'reason':'EPOCH_NOT_LIVE','activationsLastHour':0,'renewals':0,
        'authorizationSequence':len(list(pathlib.Path(cfg['authorizationRoot']).glob('*.signature.json'))),
        'epochs':{'adapter':None,'southbound':None},'updatedAt':0}
    path=pathlib.Path(cfg['statusPath']); path.write_text(json.dumps(status,sort_keys=True,separators=(',',':')))
    path.chmod(0o600)
elif args==['disable','--now',unit]: state.write_text('inactive')
elif args[:2]==['show',unit]:
    active=state.read_text() if state.exists() else 'inactive'
    load=loaded.read_text() if loaded.exists() else ('loaded' if unitpath.exists() else 'not-found')
    print('ActiveState='+active+'\nSubState='+('running' if active=='active' else 'dead')+
        '\nFragmentPath='+(str(unitpath) if load=='loaded' else '')+
        '\nNeedDaemonReload=no\nDropInPaths=\nLoadState='+load)
else: raise SystemExit(2)
'''


class PortableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.composed = C.compose(F.issuance.fixtures.fixture())

    def head(self, sequence=1, **changes):
        payload = json.loads(self.composed['authorization'])
        if sequence > 1:
            payload.update(sequence=sequence, supersedes=A.sha(self.composed['authorization']), issuedAt=payload['issuedAt']+1)
        payload.update(changes)
        raw = A.canonical(payload)
        return {'sequence': sequence, 'decision': payload['decision'], 'sha256': A.sha(raw), 'authorization': payload}, raw

    def test_entire_head_payload_matches_for_sequence_one_and_two(self):
        for sequence in (1, 2):
            head, raw = self.head(sequence)
            self.assertEqual(I.payload_match(self.composed, head, raw),
                {'sequence': sequence, 'sha256': A.sha(raw), 'decision': 'OPERATE', 'payloadByteMatch': True})

    def test_changed_document_or_any_other_payload_field_is_denied(self):
        for change in ({'runtimeConfigurationSha256': '0'*64}, {'acceptanceSha256': '0'*64},
                       {'installationRef': 'other'}, {'lease': {'ownerConfigurationSha256': '0'*64}}):
            head, raw = self.head(2, **change)
            with self.subTest(change=change), self.assertRaisesRegex(A.OperationDenied, 'R3_AUTHORIZATION_PAYLOAD_MISMATCH'):
                I.payload_match(self.composed, head, raw)
        head, raw = self.head()
        with self.assertRaisesRegex(A.OperationDenied, 'R3_AUTHORIZATION_PAYLOAD_MISMATCH'):
            I.payload_match(self.composed, head, raw+b'\n')

    def test_stop_is_denied_with_dedicated_code(self):
        head, raw = self.head(2, decision='STOP')
        with self.assertRaisesRegex(A.OperationDenied, 'R3_AUTHORIZATION_NOT_OPERATE'):
            I.payload_match(self.composed, head, raw)

    def test_unit_exec_and_required_restrictions(self):
        cfg = json.loads(self.composed['documents']['runtime-configuration.json'])
        sup = json.loads(self.composed['documents']['supervisor/configuration.json'])
        with patch.object(I, 'Path', PurePosixPath):
            raw = I.unit_bytes(PurePosixPath('/etc/ouf/install'), cfg, sup).decode()
        self.assertIn('ExecStart='+cfg['pythonPath']+' -I -B /etc/ouf/install/source/scripts/semantic-provider-lease-supervisor-v2.py', raw)
        self.assertIn('--configuration-sha256 '+cfg['leaseQuiesce']['configuration']['sha256'], raw)
        for line in ('User=root', 'Restart=always', 'NoNewPrivileges=yes', 'BindsTo=docker.service',
                     'After=docker.service ouf-semantic-boot-guard.service', 'ProtectSystem=full'):
            self.assertIn(line+'\n', raw)
        self.assertIn(str(PurePosixPath(sup['coordinator']['journalPath']).parent), raw)

    def test_only_public_errors_and_argument_failures(self):
        for restore in (False, True):
            output, errors = io.StringIO(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                self.assertEqual(I.main(['--unknown', 'PRIVATE_SENTINEL'], restore), 1)
            self.assertEqual(json.loads(output.getvalue())['reason'], 'INVALID_ARGUMENTS')
            self.assertNotIn('PRIVATE_SENTINEL', output.getvalue())
            self.assertEqual(errors.getvalue(), '')
        self.assertEqual(I.public(ValueError('PRIVATE_SENTINEL')), 'R3_INPUT_OR_IO_UNPROVEN')

    def test_scope_restores_imported_package_bindings(self):
        import tools
        saved = sys.modules.copy()
        with I.module_scope():
            sys.modules['r3_scope_probe'] = object()
            tools.r3_scope_probe = object()
        self.assertEqual(sys.modules, saved)
        self.assertFalse(hasattr(tools, 'r3_scope_probe'))

    def test_fake_native_programs_compile(self):
        for raw in (DOCKER, SYSTEMCTL):
            compile(F.render(execution_fixture.EXEC_PROBE + raw, BASE='/var/lib/fixture'), '<fake-command>', 'exec')

    def test_switch_import_resolves_unchanged_legacy_contracts_from_delivery(self):
        # Only import resolution is portable; no flock or custody is simulated.
        with I.module_scope(), patch.object(sys, 'path', list(sys.path)):
            if sys.platform == 'linux':
                switch = I.native_switch()
            else:
                with patch.dict(sys.modules, {'fcntl': SimpleNamespace()}):
                    switch = I.native_switch()
            self.assertEqual(Path(switch.__file__).resolve(), ROOT / 'tools/semantic_transaction_profiles/guarded_runtime_switch.py')
            self.assertTrue(callable(switch.switch_existing_wrapper))

    def test_first_exclusive_open_marks_effect_even_when_write_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            report = {'doNotRerunApply': False}
            with patch.object(I.os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True), \
                    patch.object(I.os, 'fchmod', create=True), \
                    patch.object(I.os, 'fdopen', side_effect=OSError(5, 'PRIVATE_SENTINEL')):
                with self.assertRaises(OSError):
                    I.write_once(Path(folder)/'partial', b'bytes', report)
            self.assertTrue(report['doNotRerunApply'])
            self.assertEqual((Path(folder)/'partial').read_bytes(), b'')


class InstallFixture(F.IntegrationFixture):
    """41a topology/recipes/runc, but publication is performed only by the installer."""
    __unittest_skip__ = False

    def setUp(self):
        F.issuance.fixtures.SOURCE_CACHE = {p: (ROOT / p).read_bytes() for p in C.SOURCE_INPUTS}
        with patch.object(F.issuance.operation, 'tempfile', SimpleNamespace(
                TemporaryDirectory=execution_fixture.executable_fixture_directory)):
            F.issuance.NativeTests.setUp(self)
        execution_fixture.execution_diagnostic(self.root)
        self.assertNotEqual(os.stat('/proc/self/ns/mnt').st_ino, os.stat('/proc/1/ns/mnt').st_ino)
        self.python = Path(sys.executable).resolve(strict=True)
        self.commands = {k: str(Path(shutil.which(k)).resolve(strict=True)) for k in ('mount', 'umount', 'unshare', 'ip')}
        subprocess.run([self.commands['mount'], '--make-rprivate', '/'], check=True)
        self.registry = self.install / 'registry'  # cleanup also works if the first exec probe fails
        self.addCleanup(self.cleanup_native)
        self.trace_python = self.script('python-trace', F.PYTHON_TRACE)
        self.script('container.py', F.CONTAINER, executable=False)
        self.runtime = self.script('runc', F.RUNC)
        self.runtime_root = self.root / 'runtime/owned'
        self.runtime_root.mkdir(parents=True, mode=0o700)
        (self.root / 'runtime').chmod(0o700)
        self.ids = {r: json.loads(self.inputs['files']['acceptance'])['roles'][r]['containerId'] for r in C.ROLES}
        self.bundles = self.root / 'bundles'
        self.bundles.mkdir(mode=0o700)
        self.make_topology()
        self.make_inputs()
        self.owner_closure()
        accepted = json.loads(self.inputs['files']['acceptance'])
        accepted['issuedAt'] = self.now - 1
        self.inputs['files']['acceptance'] = A.canonical(accepted)+b'\n'
        self.publish_inputs()
        self.composed = C.compose(self.inputs)
        plan = self.issuer_cli(self.argv())
        self.issuer_cli(self.argv('--apply', plan['planSha256']))
        self.authority_bytes = {p.name: p.read_bytes() for p in self.chain.iterdir()}
        self.prepare_v51()
        self.wrapper = self.root / 'ouf-semantic-admitted-v2'
        self.old_wrapper = I.wrapper_bytes(str(self.python), self.v51, V.RUNTIME)
        self.write(self.wrapper, self.old_wrapper, 0o755)
        self.guard = self.root / 'guard.lock'
        self.write(self.guard, b'')
        self.docker = self.script('docker', DOCKER)
        self.frames = {cid: {'Id': cid, 'Image': 'sha256:'+'1'*64,
            'State': {'Status': 'created', 'Running': False, 'Pid': 0, 'StartedAt': '0001-01-01T00:00:00Z'},
            'RestartCount': 0, 'Config': {'MacAddress': '02:00:00:00:01:02'}, 'HostConfig': {}, 'Mounts': []}
            for cid in self.ids.values()}
        self.write(self.root / 'docker-state.json', A.canonical(self.frames))
        self.systemctl = self.script('systemctl', SYSTEMCTL)
        # Fixed production unit path, isolated by a private mount, never a CLI override.
        units = self.root / 'systemd'
        units.mkdir(mode=0o700)
        self.native_command('mount', '--bind', str(units), '/etc/systemd/system')
        self.install_output = self.root / 'installed'
        self.restore_output = self.root / 'restored'

    def script(self, name, source, executable=True, **values):
        item = super().script(name, execution_fixture.EXEC_PROBE + source if executable else source,
                              executable=executable, **values)
        if executable:
            probe = execution_fixture.diagnostic_run([item['path'], '--fixture-exec-probe'],
                capture_output=True, timeout=5, env=V.ENV)
            self.assertEqual(probe.returncode, 0, probe.stderr.decode('utf-8', 'replace'))
        return item

    def owner_closure(self):
        owner = json.loads(self.inputs['files']['coordinator'])
        names = ('materialize_southbound_kernel', 'semantic_provider_dns', 'materialize_southbound_lease_refresh',
                 'semantic_provider_lease_nft', 'semantic_provider_lease_owner', 'semantic_provider_lease_coordination')
        sources = {'tools/'+name+'.py': (ROOT / 'tools/semantic_cohort_admission/cohort-draft/tools' / (name+'.py')).read_bytes()
                   for name in names}
        # Historical launcher/supervise are verified by the real closure loader;
        # runtime(configuration) never calls their legacy service loop.
        sources.update({'scripts/run_semantic_coordinated_lease_owner.py': b'# fixture historical launcher\n',
                        'tools/semantic_provider_coordinated_supervisor.py': b'# fixture unused historical loop\n'})
        for name, raw in sources.items():
            path = self.root / 'source' / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.write(path, raw)
        owner.update(sourceHashes={name: A.sha(raw) for name, raw in sources.items()}, readBudgetSeconds=2)
        self.inputs['files']['coordinator'] = A.canonical(owner)
        self.write(self.owner, self.inputs['files']['coordinator'])
        settings = json.loads(self.inputs['files']['settings'])
        settings['coordinatorBinding']['sha256'] = A.sha(self.inputs['files']['coordinator'])
        self.inputs['files']['settings'] = A.canonical(settings)

    def prepare_v51(self):
        self.v51 = self.root / 'v51'
        self.v51.mkdir(mode=0o700)
        for name in V.CLOSURE:
            path = self.v51 / 'source' / name
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            raw = (ROOT / name).read_bytes()
            self.assertEqual(A.sha(raw), V.CLOSURE[name])
            self.write(path, raw)
        (self.v51 / 'arming').mkdir(mode=0o700)
        accepted = self.root / 'acceptance.json'
        raw = self.inputs['files']['acceptance']
        self.write(accepted, raw)
        header = {'schema': self.m.SIGNATURE_SCHEMA, 'algorithm': 'Ed25519', 'keyRef': 'key-a',
                  'role': 'ARTIFACT_ACCEPTANCE', 'issuerRef': 'installer', 'installationRef': 'inst',
                  'entityRef': 'ent', 'payloadHash': A.sha(raw)}
        frame = self.root / 'acceptance-frame'
        self.write(frame, self.m.signing_bytes(raw, header))
        signature = self.native('pkeyutl', '-sign', '-rawin', '-inkey', str(self.keys['key-a']), '-in', str(frame)).hex()
        self.acceptance_signature = self.root / 'acceptance.signature.json'
        self.write(self.acceptance_signature, A.canonical({**header, 'signature': signature}))
        for name in ('old-driver.py', 'old-broker.py'):
            self.write(self.root / name, b'# fixture inactive v51\n')
        binding = lambda p: {'path': str(p), 'sha256': A.sha(p.read_bytes())}
        config = {'schema': V.V51_SCHEMA, 'sourceHash': V.CLOSURE[V.RUNTIME],
            'runtimePath': self.runtime['path'], 'runtimeSha256': self.runtime['sha256'],
            'pythonPath': str(self.python), 'pythonSha256': A.sha(self.python.read_bytes()),
            'driverPath': str(self.root / 'old-driver.py'), 'driverSha256': A.sha((self.root / 'old-driver.py').read_bytes()),
            'admissionPath': str(self.root / 'old-broker.py'), 'admissionSha256': A.sha((self.root / 'old-broker.py').read_bytes()),
            'registryRoot': str(self.root), 'runtimeStateRoot': str(self.runtime_root.parent),
            'acceptance': binding(accepted), 'b1b2Anchor': self.anchor, 'mandateRoot': str(self.ledger_root),
            'armingRoot': str(self.v51 / 'arming'), 'armingVerifierPath': str(self.v51 / 'source' / V.VERIFIER),
            'armingVerifierSha256': V.CLOSURE[V.VERIFIER],
            'b1b2AuthorityModule': binding(self.v51 / 'source' / V.MANDATES), 'opensslBinding': self.ssl,
            'armingIssuerRef': 'installer',
            'candidates': {cid: {'phase': 'INACTIVE', 'bundleParents': [str(self.bundles)]} for cid in self.ids.values()}}
        self.write(self.v51 / 'runtime-configuration.json', A.canonical(config))

    def install_args(self, mode='--plan', digest=None):
        result = [mode, '--install-root', str(self.install), '--v51-root', str(self.v51),
            '--wrapper', str(self.wrapper), '--current-wrapper-sha256', A.sha(self.old_wrapper),
            '--lock', str(self.guard), '--docker', self.docker['path'], '--docker-sha256', self.docker['sha256'],
            '--docker-socket', 'unix:///fixture/docker.sock', '--systemctl', self.systemctl['path'],
            '--systemctl-sha256', self.systemctl['sha256'], '--output-directory', str(self.install_output),
            '--inputs', str(self.mapping), '--inputs-sha256', A.sha(self.mapping.read_bytes()),
            '--issued-at', str(self.now), '--table-name', 'adapter=ouf_r3_adapter', 'southbound=ouf_r3_southbound',
            '--acceptance-signature', str(self.acceptance_signature),
            '--acceptance-signature-sha256', A.sha(self.acceptance_signature.read_bytes())]
        return result + (['--plan-sha256', digest] if digest else [])

    def restore_args(self, mode='--plan', digest=None):
        args = self.install_args()
        args = args[:args.index('--inputs')]
        args[0] = mode
        args[args.index('--current-wrapper-sha256')+1] = A.sha(self.wrapper.read_bytes())
        args[args.index('--output-directory')+1] = str(self.restore_output)
        args += ['--prior-wrapper-sha256', A.sha(self.old_wrapper), '--installation-output-directory', str(self.install_output)]
        return args + (['--plan-sha256', digest] if digest else [])

    def cli(self, args, restore=False, code=0):
        script = 'restore-semantic-provider-r3.py' if restore else 'install-semantic-provider-r3.py'
        result = subprocess.run([str(self.python), '-I', '-B', str(ROOT / 'scripts' / script), *args],
                                capture_output=True, timeout=150)
        if result.returncode != code:
            # The CLI sanitizes exceptions in its own process. Correlate its
            # public errno/callChain with these fixture executable paths; probe
            # directly to retain a kernel errno if execution is still denied.
            for item in (self.docker, self.systemctl, self.runtime, self.trace_python):
                execution_fixture.execution_diagnostic(item['path'])
                try:
                    execution_fixture.diagnostic_run([item['path'], '--fixture-exec-probe'],
                        capture_output=True, timeout=5, env=V.ENV)
                except (OSError, subprocess.TimeoutExpired):
                    # Already logged; keep the original CLI report in the
                    # assertion below, including its public errno/callChain.
                    pass
        self.assertEqual(result.returncode, code, result.stdout.decode()+result.stderr.decode())
        self.assertEqual(result.stderr, b'')
        return json.loads(result.stdout)

    def installed(self):
        plan = self.cli(self.install_args())
        self.assertEqual(plan, self.cli(self.install_args()))
        self.assertFalse(self.install_output.exists())
        self.assertEqual(set(p.name for p in self.install.iterdir()), {'authorization'})
        result = self.cli(self.install_args('--apply', plan['planSha256']))
        self.assertEqual(result['status'], 'SEMANTIC_PROVIDER_R3_INSTALLED_WAITING')
        self.assertTrue(result['doNotRerunApply'])
        self.assertEqual(self.wrapper.read_bytes(), plan['wrapperProposed']['text'].encode())
        self.assertEqual(Path('/etc/systemd/system/'+I.UNIT).read_bytes(), plan['unit']['text'].encode())
        self.assertEqual((self.root / 'unit-active').read_text(), 'active')
        self.assertEqual({p.name: p.read_bytes() for p in self.chain.iterdir()}, self.authority_bytes)
        for row in plan['writes']['files']:
            self.assertEqual(Path(row['path']).stat().st_mode & 0o777, 0o600)
            self.assertEqual(A.sha(Path(row['path']).read_bytes()), row['sha256'])
        calls = [json.loads(line) for line in (self.root / 'runc.jsonl').read_text().splitlines()]
        self.assertEqual(calls, [['--version'], ['--version']])
        self.assertTrue(all(json.loads(line)[2]=='inspect' for line in (self.root / 'docker.jsonl').read_text().splitlines()))
        return result

    def scenario_install_restore(self):
        self.installed()
        installation = {str(p.relative_to(self.install)): p.read_bytes() for p in self.install.rglob('*') if p.is_file()}
        plan = self.cli(self.restore_args(), restore=True)
        result = self.cli(self.restore_args('--apply', plan['planSha256']), restore=True)
        self.assertEqual(result['status'], 'SEMANTIC_PROVIDER_R3_RESTORED_V51')
        self.assertEqual(self.wrapper.read_bytes(), self.old_wrapper)
        self.assertEqual((self.root / 'unit-active').read_text(), 'inactive')
        self.assertFalse(I.UNIT_PATH.exists())
        self.assertEqual(result['unitLoadState'], 'not-found')
        archived = self.restore_output / I.UNIT
        self.assertEqual(A.sha(archived.read_bytes()), plan['unitSha256'])
        self.assertEqual(result['retiredUnit'], {'path': str(archived), 'sha256': plan['unitSha256']})
        calls = [json.loads(line) for line in (self.root / 'systemctl.jsonl').read_text().splitlines()]
        disable = calls.index(['disable', '--now', I.UNIT])
        self.assertEqual(calls[disable+1][0], 'show')
        self.assertEqual(calls[disable+2], ['daemon-reload'])
        self.assertEqual(calls[disable+3][0], 'show')
        self.assertEqual(installation, {str(p.relative_to(self.install)): p.read_bytes() for p in self.install.rglob('*') if p.is_file()})

    def scenario_restore_reinstall_new_root(self):
        self.scenario_install_restore()
        old_chain = self.chain
        old_authority = {p.name: p.read_bytes() for p in old_chain.iterdir()}
        archived = (self.restore_output / I.UNIT).read_bytes()
        self.install = self.root / 'semantic-provider-r3-install-v2'
        self.install.mkdir(mode=0o700)
        self.chain = self.install / 'authorization'
        self.output = self.root / 'issued-v2'
        self.install_output = self.root / 'installed-v2'
        settings = json.loads(self.inputs['files']['settings'])
        settings['installRoot'] = str(self.install)
        self.inputs['files']['settings'] = A.canonical(settings)
        self.publish_inputs()
        self.composed = C.compose(self.inputs)
        plan = self.issuer_cli(self.argv())
        self.issuer_cli(self.argv('--apply', plan['planSha256']))
        new_authority = {p.name: p.read_bytes() for p in self.chain.iterdir()}
        self.assertNotEqual(new_authority['1.json'], old_authority['1.json'])
        self.assertEqual(json.loads(new_authority['1.json'])['sequence'], 1)
        plan = self.cli(self.install_args())
        result = self.cli(self.install_args('--apply', plan['planSha256']))
        self.assertEqual(result['status'], 'SEMANTIC_PROVIDER_R3_INSTALLED_WAITING')
        self.assertEqual(result['installRoot'], str(self.install))
        self.assertEqual(self.wrapper.read_bytes(), plan['wrapperProposed']['text'].encode())
        self.assertEqual(I.UNIT_PATH.read_bytes(), plan['unit']['text'].encode())
        self.assertIn(str(self.install).encode(), I.UNIT_PATH.read_bytes())
        self.assertEqual({p.name: p.read_bytes() for p in old_chain.iterdir()}, old_authority)
        self.assertEqual({p.name: p.read_bytes() for p in self.chain.iterdir()}, new_authority)
        self.assertEqual((self.restore_output / I.UNIT).read_bytes(), archived)

    def scenario_drift(self):
        plan = self.cli(self.install_args())
        mutations = [('R3_WRAPPER_DRIFT', self.wrapper, b'#!/bin/sh\nexit 99\n'),
                     ('GUARD_LOCK_NOT_EMPTY', self.guard, b'occupied'),
                     ('R3_COORDINATOR_NOT_QUIESCED', Path(json.loads(self.inputs['files']['coordinator'])['journalFile']),
                      self.inputs['files']['coordinationJournal'].replace(b'QUIESCED', b'BLOCKED'))]
        for reason, path, raw in mutations:
            original = path.read_bytes()
            self.write(path, raw, 0o755 if path == self.wrapper else 0o600)
            held = self.cli(self.install_args('--apply', plan['planSha256']), code=1)
            self.assertEqual(held['reason'], reason)
            self.assertFalse(held['doNotRerunApply'])
            self.write(path, original, 0o755 if path == self.wrapper else 0o600)
        self.write(self.install / 'foreign', b'preserve')
        held = self.cli(self.install_args(), code=1)
        self.assertEqual(held['reason'], 'R3_INSTALL_ROOT_NOT_AUTHORIZATION_ONLY')
        (self.install / 'foreign').unlink()
        row = self.frames[self.ids['adapter']]
        row['State']['StartedAt'] = '2026-11-15T00:00:00Z'
        self.write(self.root / 'docker-state.json', A.canonical(self.frames))
        self.assertEqual(self.cli(self.install_args(), code=1)['reason'], 'SUCCESSOR_EVER_STARTED')
        row['State']['StartedAt'] = '0001-01-01T00:00:00Z'
        self.write(self.root / 'docker-state.json', A.canonical(self.frames))
        self.assertEqual(self.cli(self.install_args('--apply', '0'*64), code=1)['reason'], 'R3_PLAN_DIGEST_CHANGED')
        self.assertFalse(self.install_output.exists())
        self.assertEqual(self.wrapper.read_bytes(), self.old_wrapper)

    def scenario_head_two(self):
        payload = json.loads(self.composed['authorization'])
        payload.update(sequence=2, supersedes=A.sha(self.composed['authorization']), issuedAt=self.now)
        self.put(2, A.canonical(payload))
        self.authority_bytes = {p.name: p.read_bytes() for p in self.chain.iterdir()}
        self.assertEqual(self.cli(self.install_args())['authorization']['sequence'], 2)
        self.installed()

    def scenario_payload_mismatch_and_stop(self):
        payload = json.loads(self.composed['authorization'])
        payload.update(sequence=2, supersedes=A.sha(self.composed['authorization']), issuedAt=self.now)
        payload['runtimeConfigurationSha256'] = '0'*64
        self.put(2, A.canonical(payload))
        self.assertEqual(self.cli(self.install_args(), code=1)['reason'], 'R3_AUTHORIZATION_PAYLOAD_MISMATCH')
        payload['decision'] = 'STOP'
        self.put(3, A.canonical({**payload, 'sequence': 3, 'supersedes': A.sha((self.chain / '2.json').read_bytes())}))
        self.assertEqual(self.cli(self.install_args(), code=1)['reason'], 'R3_AUTHORIZATION_NOT_OPERATE')
        self.assertFalse(self.install_output.exists())

    def scenario_epoch_denies_restore(self):
        self.installed()
        for cid in self.ids.values():
            epoch = self.registry / cid / 'epochs/1'
            epoch.mkdir(mode=0o700)
            held = self.cli(self.restore_args(), restore=True, code=1)
            self.assertEqual(held['reason'], 'R3_EPOCH_PRESENT_RESTORE_DENIED')
            epoch.rmdir()
            self.write(self.registry / cid / 'current', b'1')
            held = self.cli(self.restore_args(), restore=True, code=1)
            self.assertEqual(held['reason'], 'R3_EPOCH_PRESENT_RESTORE_DENIED')
            (self.registry / cid / 'current').unlink()
            (self.registry / cid / 'current').symlink_to('missing-pointer-target')
            held = self.cli(self.restore_args(), restore=True, code=1)
            self.assertEqual(held['reason'], 'R3_EPOCH_PRESENT_RESTORE_DENIED')
            (self.registry / cid / 'current').unlink()
        self.assertFalse(self.restore_output.exists())

    def scenario_partial_claim(self):
        self.write(self.root / 'enable-fail', b'fixture failure')
        plan = self.cli(self.install_args())
        held = self.cli(self.install_args('--apply', plan['planSha256']), code=1)
        self.assertEqual(held['reason'], 'R3_SYSTEMCTL_FAILED')
        self.assertTrue(held['doNotRerunApply'])
        self.assertEqual(self.wrapper.read_bytes(), self.old_wrapper)
        self.assertTrue((self.install_output / 'result.json').exists())
        self.assertTrue(self.cli(self.install_args('--apply', plan['planSha256']), code=1)['doNotRerunApply'])

    def scenario_wrapper_create_reaches_real_broker(self):
        self.installed()
        cid = self.ids['adapter']
        result = subprocess.run([str(self.wrapper), '--root', str(self.runtime_root), 'create', '--bundle',
            str(self.bundles / cid), cid], capture_output=True, timeout=40)
        self.assertEqual(result.returncode, 0, self.diagnostic()+result.stderr.decode())
        self.assertEqual(self.row()['state'], 'CREATED')
        self.assertEqual(self.row()['epoch'], 1)
        calls = [json.loads(line)['argv'] for line in (self.root / 'python.jsonl').read_text().splitlines()
                 if json.loads(line)['event']=='invoke']
        self.assertTrue(any(argv[2].endswith('semantic-provider-deployment-broker-v2.py')
                            and argv[-2:]==['--mode', 'authorize-create'] for argv in calls))
        self.assertEqual({p.name: p.read_bytes() for p in self.chain.iterdir()}, self.authority_bytes)
        self.assertEqual(self.cli(self.restore_args(), restore=True, code=1)['reason'], 'R3_EPOCH_PRESENT_RESTORE_DENIED')


SCENARIOS = ('scenario_install_restore', 'scenario_restore_reinstall_new_root', 'scenario_drift', 'scenario_head_two', 'scenario_payload_mismatch_and_stop',
             'scenario_epoch_denies_restore', 'scenario_partial_claim', 'scenario_wrapper_create_reaches_real_broker')


@unittest.skipUnless(NATIVE, 'set OUF_R3_INSTALL_NATIVE=1 under Linux root:root')
class NativeTests(unittest.TestCase):
    def scenario(self, name):
        for command in ('unshare', 'mount', 'umount', 'ip', 'openssl'):
            self.assertIsNotNone(shutil.which(command), 'required native fixture command: '+command)
        result = subprocess.run([shutil.which('unshare'), '--mount', '--net', '--fork', sys.executable,
            '-I', '-B', str(Path(__file__).resolve()), '--native-child', name], capture_output=True, timeout=300)
        # Successful child output is otherwise hidden by unittest; always show
        # the actual temporary-directory mount in CI, not just /var/lib's mount.
        for line in result.stderr.decode('utf-8', 'replace').splitlines():
            if line.startswith('FIXTURE_EXEC_DIAGNOSTIC='):
                print(line, file=sys.stderr)
        self.assertEqual(result.returncode, 0, result.stdout.decode()+result.stderr.decode())


for _scenario in SCENARIOS:
    setattr(NativeTests, 'test_'+_scenario.removeprefix('scenario_'), lambda self, name=_scenario: self.scenario(name))


def load_tests(loader, tests, pattern):
    return unittest.TestSuite([loader.loadTestsFromTestCase(PortableTests), loader.loadTestsFromTestCase(NativeTests)])


if __name__ == '__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--native-child':
        if not NATIVE or sys.argv[2] not in SCENARIOS:
            raise RuntimeError('unknown/disabled native scenario')
        result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([InstallFixture(sys.argv[2])]))
        raise SystemExit(0 if result.wasSuccessful() else 1)
    unittest.main()
