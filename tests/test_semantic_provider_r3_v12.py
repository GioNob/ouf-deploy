"""D-050 local fixtures: frozen replay, generation-2 closure and lifecycle gates."""
from contextlib import contextmanager
import copy
import json
import os
import stat
from pathlib import Path, PurePosixPath
import sys
import subprocess
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]
from tools.semantic_provider_r3 import compose as C, install_common as I, upgrade as U, operate as O
from tools.semantic_lease_kernel_migration import migration as M, boot_dispatcher as K
from tools.semantic_lease_kernel_migration import native as N
import test_semantic_provider_r3_compose as F
import test_semantic_provider_r3_operate as OF
from test_semantic_lease_dns_tolerance import kernel_configuration
from test_semantic_lease_kernel_migration import fixture_tables

NATIVE = os.environ.get('OUF_LEASE_KERNEL_V2_NATIVE') == '1'
if NATIVE and (sys.platform != 'linux' or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError('OUF_LEASE_KERNEL_V2_NATIVE requires Linux root:root; refusing to skip')


def blob(path):
    return (ROOT / path).read_bytes().replace(b'\r\n', b'\n')


def fixture(*, dispatcher_raw=None):
    dispatcher_raw = blob(K.__file__) if dispatcher_raw is None else dispatcher_raw
    old = F.fixture(11)
    prior = C.document(old['files']['coordinator'])
    kernel = kernel_configuration()
    kernel.update(tableName='ouf_sem_provider', guardedInterfaces=['oufsp-int', 'oufsp-egress'],
                  existingInterfaces=['br-backend'])
    kernel['staticFlows'] = [{'purpose': 'GATEWAY_ADAPTER', 'source': '172.21.0.2',
        'destination': '172.21.0.3', 'protocol': 'tcp', 'port': 9443}]
    kernel['providerFlows'][1]['source'] = '172.22.0.3'
    names = ('materialize_southbound_kernel', 'semantic_provider_dns', 'materialize_southbound_lease_refresh',
             'semantic_provider_lease_nft', 'semantic_provider_lease_owner', 'semantic_provider_lease_coordination')
    retained = {'tools/' + n + '.py': blob('tools/semantic_cohort_admission/cohort-draft/tools/' + n + '.py')
                for n in names}
    retained['tools/semantic_provider_coordinated_supervisor.py'] = blob('tools/semantic_lease_recovery/adaptive_supervisor.py')
    retained['scripts/run_semantic_coordinated_lease_owner.py'] = b'# synthetic entrypoint; not executed\n'
    prior.update(kernel=kernel, readBudgetSeconds=1, pollSeconds=15, sourceHashes={p: C.sha(b) for p, b in retained.items()})
    old['files']['coordinator'] = C.canonical(prior)
    settings = C.document(old['files']['settings'])
    settings['coordinatorBinding']['sha256'] = C.sha(old['files']['coordinator'])
    old['files']['settings'] = C.canonical(settings)
    v11 = C.compose(old, 11, sequence=11, supersedes='a' * 64)
    # Native.old_sources() merges the two historical boot sources into the
    # generation-2 owner closure; they are retained, never executed by R3.
    boot_sources = {'scripts/run_semantic_coordinated_boot_guard.py': b'# sealed historical boot entrypoint\n',
                    'tools/semantic_provider_boot_coordination.py': b'# sealed historical boot coordination\n'}
    retained.update(boot_sources)
    inputs = copy.deepcopy(old)
    root, claim = '/etc/ouf/generations/g2', '/etc/ouf/migrations/one-two'
    destination = M.destination(kernel, 2)
    after = fixture_tables(destination)
    after_seals = M.seals(destination, after)
    plan = M.digest_plan({'schema': M.SCHEMA, 'operation': 'migrate', 'context': {'owner': prior,
        'units': {}, 'pointerRaw': '{}',
        'profile': {'coordinatedConfiguration': settings['coordinatorBinding']['path'],
                    'sourceHashes': {p: C.sha(raw) for p, raw in boot_sources.items()}}},
        'observation': {'authorization': {'sequence': 11, 'sha256': C.sha(v11['authorization']), 'decision': 'OPERATE'}},
        'destination': destination, 'paths': {'generationDirectory': root, 'migrationDirectory': claim,
            'dispatcher': '/etc/ouf/lease-kernel-boot-dispatcher-v1.py', 'r3': {'install_root': settings['installRoot']}},
        'before': M.seals(kernel, fixture_tables(kernel)), 'expectedBootFootprint': after_seals['boot'],
        'sourceHashes': {'@dispatcher': C.sha(dispatcher_raw)}})
    retained.update({'tools/materialize_southbound_kernel_v2.py': blob(C.KERNEL_V2),
                     'tools/materialize_southbound_lease_refresh_v2.py': blob(C.REFRESH_V2)})
    owner = copy.deepcopy(prior)
    owner.update(kernel=destination, expectedStructureHash=after_seals['structure'],
                 journalFile=root + '/coordination-journal.json', sourceHashes={p: C.sha(b) for p, b in retained.items()})
    owner.pop('binding')
    owner['binding'] = {'transactionId': plan['planSha256'], 'configurationHash': K.digest(owner),
                        'leaseStructureHash': owner['expectedStructureHash']}
    files = inputs['files']
    files['coordinator'] = C.canonical(owner)
    settings['coordinatorBinding'] = {'path': root + '/coordinated-configuration.json', 'sha256': C.sha(files['coordinator'])}
    files['settings'] = C.canonical(settings)
    files['coordinationJournal'] = C.canonical({'schema': 'ouf.semantic-lease-coordination.v1', **owner['binding'],
        'state': 'QUIESCED', 'leaseAuthorized': False, 'startAuthorized': False, 'leaseAddresses': [[], []]})
    receipt = {'schema': M.SCHEMA, 'status': 'LEASE_KERNEL_MIGRATED', 'planSha256': plan['planSha256'],
        'before': plan['before'], 'after': after_seals, 'journal': 'QUIESCED', 'doNotRerunApply': True,
        'startAuthorized': False, 'leaseAuthorized': False}
    generation = {'schema': 'ouf.semantic-lease-kernel-generation.v1', 'directory': root, 'generation': 2,
        'closure': {'coordinated-configuration.json': C.sha(files['coordinator']),
                    **{'source/' + p: C.sha(raw) for p, raw in retained.items()}},
        'configurationHash': C.sha(files['coordinator']), 'bootProfileHash': 'f' * 64,
        'bootProfile': {'path': root + '/boot-profile.json', 'sha256': 'f' * 64}, 'runner': 'boot-runner-v2.py',
        'predecessorTableName': kernel['tableName'], 'migrationPlanSha256': plan['planSha256']}
    files.update(migrationPlan=C.canonical(plan), migrationReceipt=C.canonical(receipt), generationReceipt=C.canonical(generation))
    files['bootPointer'] = C.canonical({'schema': 'ouf.semantic-coordinated-boot-pointer.v1',
        'receiptFile': root + '/generation-receipt.json', 'receiptHash': C.sha(files['generationReceipt']),
        'observerFile': plan['paths']['dispatcher'], 'observerHash': plan['sourceHashes']['@dispatcher']})
    inputs['sources'] = {p: blob(p) for p in C.SOURCE_INPUTS_V12}
    return inputs, v11, retained, after


def composed(inputs, previous):
    return C.compose(inputs, 12, sequence=12, supersedes=C.sha(previous['authorization']))


class Composition(unittest.TestCase):
    def test_composition_accepts_real_task65_stage_publication(self):
        # Native.stage hashes the loaded checkout file when it builds the pointer.
        inputs, old, retained, tables = fixture(dispatcher_raw=Path(K.__file__).read_bytes())
        plan = C.document(inputs['files']['migrationPlan'])
        # Use the real task-65 producer; replace only its filesystem effects.
        io = object.__new__(N.Native)
        io.generation = PurePosixPath(plan['paths']['generationDirectory'])
        io.owner = plan['context']['owner']
        io.boot = {}; io.profile = plan['context']['profile']; io.manifest = {'units': {}}
        io.dispatcher = PurePosixPath(plan['paths']['dispatcher'])
        hashes = {'source/' + p: C.sha(raw) for p, raw in retained.items()}
        hashes['boot-runner-v2.py'] = C.sha(blob('tools/semantic_lease_kernel_migration/boot_runner_v2.py'))
        io.source_hashes = lambda: hashes
        io.proposed_units = lambda context: {}
        writes = {}
        with patch.object(K, 'write_once', side_effect=lambda p, raw: writes.__setitem__(str(p), raw)):
            publication = io.stage(plan, tables)
        files = inputs['files']; root = str(io.generation)
        files['coordinator'] = writes[root + '/coordinated-configuration.json']
        files['coordinationJournal'] = writes[root + '/coordination-journal.json']
        files['generationReceipt'] = writes[root + '/generation-receipt.json']
        files['bootPointer'] = publication[-1]['new'].encode('ascii')
        settings = C.document(files['settings'])
        settings['coordinatorBinding']['sha256'] = C.sha(files['coordinator'])
        files['settings'] = C.canonical(settings)
        self.assertEqual(C.document(composed(inputs, old)['authorization'])['sequence'], 12)

    def test_all_v1_v11_output_and_input_bytes_pinned_before_changes(self):
        golden = json.loads(blob('tests/fixtures/r3-v1-v11-pre-v12-hashes.json'))
        for v in range(1, 12):
            with self.subTest(version=v):
                r = C.compose(F.fixture(v), v, **({} if v == 1 else dict(sequence=v, supersedes='a' * 64)))
                self.assertEqual({k: r[k] for k in ('hashes', 'inputHashes')}, golden[str(v)])

    def test_v12_owner_nics_peers_kernel_and_refresh(self):
        inputs, old, _, _ = fixture()
        original = copy.deepcopy(inputs)
        r = composed(inputs, old)
        self.assertEqual(r, composed(inputs, old))
        self.assertEqual(inputs, original)
        owner = C.document(inputs['files']['coordinator'])
        payload = C.document(r['authorization'])
        self.assertEqual(payload['lease']['ownerConfigurationSha256'], C.sha(inputs['files']['coordinator']))
        self.assertEqual(payload['lease']['leaseStructureHash'], owner['expectedStructureHash'])
        prefix = 'versions/12/'
        for role in C.ROLES:
            t = C.document(r['documents'][prefix + 'documents/' + role + '/preparer-template.json'])
            nics = t['candidate']['networkBindings'] + [n for f in t['candidate']['transport']
                if f['peerIngress']['kind'] == 'CREATED_CANDIDATE' for n in f['peerIngress']['declaration']['networkBindings']]
            for nic in nics:
                if 'leaseGuard' in nic:
                    self.assertEqual(nic['leaseGuard'], {'tableName': owner['kernel']['tableName'],
                        'configurationHash': C.lease_guard_hash(owner['kernel'])})
        compiler = C.contract_module(r['documents'][prefix + 'source/tools/materialize_southbound_kernel.py'], 'g2_alias')
        self.assertIn('ct original ip daddr', compiler.materialize(owner['kernel'], empty_provider_sets=True)['nftRules'])
        with I.module_scope(), patch.dict(sys.modules, {'tools.materialize_southbound_kernel': compiler}):
            refresh = C.contract_module(r['documents'][prefix + 'source/tools/materialize_southbound_lease_refresh.py'], 'g2_refresh')
            self.assertTrue(refresh.compile_refresh(owner['kernel'], [], 100, apply_budget_seconds=1)['denyOnly'])

    def test_receipt_pointer_owner_and_state_drift_denied(self):
        inputs, old, _, _ = fixture()
        for key, field, value, code in (
            ('migrationReceipt', 'status', 'HELD', 'MIGRATION_STATE_DENIED'),
            ('migrationReceipt', 'planSha256', '0' * 64, 'MIGRATION_DRIFT'),
            ('generationReceipt', 'configurationHash', '0' * 64, 'MIGRATION_DRIFT'),
            ('bootPointer', 'receiptHash', '0' * 64, 'MIGRATION_DRIFT'),
            ('bootPointer', 'receiptFile', '/foreign/receipt.json', 'MIGRATION_DRIFT')):
            bad = copy.deepcopy(inputs)
            d = C.document(bad['files'][key]); d[field] = value
            bad['files'][key] = C.canonical(d)
            with self.subTest(key=key, field=field), self.assertRaisesRegex(RuntimeError, code):
                composed(bad, old)
        bad = copy.deepcopy(inputs); bad['files'].pop('migrationReceipt')
        with self.assertRaisesRegex(RuntimeError, 'EXACT_R3_INPUT_SET_REQUIRED'): composed(bad, old)
        final = C.document(inputs['files']['migrationReceipt'])
        final.update(status='LEASE_KERNEL_FINALIZED', migrationPlanSha256=final['planSha256'], planSha256='f' * 64)
        inputs['files']['migrationReceipt'] = C.canonical(final)
        self.assertEqual(C.document(composed(inputs, old)['authorization'])['sequence'], 12)

    def test_real_broker_loader_executes_closed_generation_2_aliases(self):
        inputs, old, _, _ = fixture(); r = composed(inputs, old)
        prefix = 'versions/12/'
        cfg = C.document(r['documents'][prefix + 'broker/adapter.json'])
        config_path = '/broker/config.json'
        disk = {cfg['sourceRoot'] + '/' + p: r['documents'][prefix + 'source/' + p] for p in cfg['sourceHashes']}
        disk[config_path] = r['documents'][prefix + 'broker/adapter.json']
        class PrivateRoot(PurePosixPath):
            def lstat(self): return types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0)
        with I.module_scope(), patch.dict(sys.modules, {'fcntl': types.ModuleType('fcntl')}), \
                patch.object(C.B, 'Path', PrivateRoot), patch.object(C.B, 'private', side_effect=lambda p: disk[str(p)]):
            loaded, raw = C.B.load(config_path)
            self.assertEqual(loaded, cfg)
            compiler = sys.modules['tools.materialize_southbound_kernel']
            owner = C.document(inputs['files']['coordinator'])
            plan = compiler.materialize(owner['kernel'], empty_provider_sets=True)
            self.assertIn('ct original', plan['nftRules'])
            profile = {**owner['dns'], 'timeoutSeconds': 10}
            instance = sys.modules['tools.semantic_provider_lease_owner'].LeaseOwner(owner['kernel'], profile, object())
            self.assertEqual(instance.configuration, owner['kernel'])
            # Source hash drift is denied by the actual broker verifier.
            disk[cfg['sourceRoot'] + '/tools/materialize_southbound_kernel.py'] += b'\n'
            with self.assertRaisesRegex(RuntimeError, 'BROKER_SOURCE_PACKAGE_DRIFT'): C.B.load(config_path)

    def test_real_sealed_supervisor_loader_supports_migrated_owner(self):
        inputs, old, retained, _ = fixture()
        r = composed(inputs, old); prefix = 'versions/12/'
        cfg = C.document(r['documents'][prefix + 'supervisor/configuration.json'])
        verified = {p: r['documents'][prefix + 'source/' + p] for p in cfg['sourceHashes']}
        root = PurePosixPath(cfg['sourceRoot'])
        owner_path = cfg['coordinator']['ownerConfiguration']['path']
        delivered = {str(root / p): raw for p, raw in verified.items()}
        delivered.update({str(PurePosixPath(owner_path).parent / 'source' / p): raw for p, raw in retained.items()})
        delivered.update({owner_path: inputs['files']['coordinator'],
            cfg['coordinator']['dnsProfile']['path']: r['documents'][prefix + 'supervisor/dns-profile.json'],
            cfg['mandatesModule']['path']: inputs['sources'][C.MANDATES]})
        def read(path, expected=None, **kw):
            raw = delivered[str(path).replace('\\', '/')]
            if expected is not None: self.assertEqual(C.sha(raw), expected)
            return raw
        sup = C.contract_module(r['documents'][prefix + 'source/' + C.SUPERVISOR], 'v12_loaded')
        actual_compile = sup.compiled
        def compile_source(*a):
            module = actual_compile(*a)
            if a[2] == 'lease_activation_core_v2':
                actual_load = module.load_installed
                def load(*a, **kw):
                    modules, saved = actual_load(*a, **kw)
                    modules['semantic_provider_lease_coordination'].PrivateJournal = lambda _: types.SimpleNamespace(read=lambda: None, write=lambda *a: None)
                    return modules, saved
                module.load_installed = load
            return module
        with I.module_scope(), patch.dict(sys.modules, {'fcntl': types.ModuleType('fcntl')}), \
                patch.object(sup, 'read_file', side_effect=read), patch.object(sup, 'compiled', side_effect=compile_source):
            coordinator, guards, factory = sup.runtime(types.SimpleNamespace(value=cfg, custody=lambda: verified))
            self.assertEqual(coordinator.configuration['generation'], 2)
            self.assertIn('ct original', sys.modules['tools.materialize_southbound_kernel'].materialize(
                coordinator.configuration, empty_provider_sets=True)['nftRules'])
            self.assertTrue(sys.modules['readback_margin_compiler'].compile_refresh(
                coordinator.configuration, [], 100, apply_budget_seconds=1)['denyOnly'])


class NativeBindingsAndUpgrade(unittest.TestCase):
    def test_live_receipt_pointer_and_quiescent_journal(self):
        inputs, old, _, _ = fixture(); files = inputs['files']
        settings = C.document(files['settings'])
        disk = {b['path']: files[k] for k, b in C.migration_bindings(files).items()}
        disk[settings['coordinatorBinding']['path']] = files['coordinator']
        journal_path = C.document(files['coordinator'])['journalFile']
        disk[journal_path] = files['coordinationJournal']
        reader = types.SimpleNamespace(bound=lambda b: disk[b['path']], read=lambda p, h: disk[p])
        with patch.object(I, 'native_switch', return_value=types.SimpleNamespace(custody=lambda p, mode: (disk[str(p)], ()))), \
                patch.object(I.os.path, 'lexists', return_value=False):
            I.coordinator_state(settings, files, reader)
            pointer_path = '/etc/ouf/coordinated-boot-installation.json'
            disk[pointer_path] = b'{}'
            with self.assertRaisesRegex(RuntimeError, 'MIGRATION_DRIFT'): I.coordinator_state(settings, files, reader)
            disk[pointer_path] = files['bootPointer']
            disk[journal_path] = C.canonical({**C.document(files['coordinationJournal']), 'state': 'BLOCKED'})
            with self.assertRaisesRegex(RuntimeError, 'NOT_QUIESCED'): I.coordinator_state(settings, files, reader)
        for marker in ('restore-receipt.json', 'finalize-intent.json'):
            with patch.object(I.os.path, 'lexists', side_effect=lambda p: str(p).replace('\\', '/').endswith('/' + marker)), \
                    self.assertRaisesRegex(RuntimeError, 'MIGRATION_STATE_DENIED'):
                I.migration_state(files, reader)

    def test_issuance_head_binding_and_closed_readers(self):
        inputs, old, _, _ = fixture()
        issuer = F.load('scripts/issue-semantic-provider-operation-authorization.py', 'v12_issuer')
        previous = {'sequence': 11, 'decision': 'OPERATE', 'sha256': C.sha(old['authorization']),
                    'authorization': C.document(old['authorization'])}
        self.assertEqual(issuer.compose_next(inputs, previous, previous['authorization']['issuedAt']), composed(inputs, old))
        previous['sha256'] = '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'MIGRATION_HEAD_DRIFT'):
            issuer.compose_next(inputs, previous, previous['authorization']['issuedAt'])
        self.assertTrue(C.input_set(inputs['files'], inputs['sources']))
        self.assertFalse(C.input_set(F.fixture(11)['files'], inputs['sources']))
        index = {'schema': 'ouf.semantic-provider-r3-inputs.v1',
                 'files': dict.fromkeys(inputs['files'], 'binding'), 'sources': dict.fromkeys(inputs['sources'], 'binding')}
        reader = Mock(); reader.read.return_value = C.canonical(index)
        reader.bound.side_effect = RuntimeError('ACCEPTED')
        with patch.object(I, 'Reader', return_value=reader), self.assertRaisesRegex(RuntimeError, 'ACCEPTED'):
            U.read_inputs(types.SimpleNamespace(inputs='/inputs', inputs_sha256='a' * 64))
        profile = {'schema': 'ouf.semantic-existing-installation-authority-bindings.v1', 'keyBindings': {}}
        reader = Mock(private_paths=set())
        reader.read.side_effect = [C.canonical(profile), C.canonical(index)]
        reader.bound.side_effect = RuntimeError('ACCEPTED')
        args = types.SimpleNamespace(private_key_path=[], authority_profile='/profile', authority_profile_sha256='a' * 64,
                                     inputs='/inputs', inputs_sha256='b' * 64)
        with patch.object(issuer, 'Reader', return_value=reader), self.assertRaisesRegex(RuntimeError, 'ACCEPTED'):
            issuer.observe(args, lambda: 0)

    @contextmanager
    def observation_fixture(self):
        inputs, old, _, _ = fixture(); r = composed(inputs, old)
        files, settings = inputs['files'], C.document(inputs['files']['settings'])
        root = PurePosixPath(settings['installRoot']); before = root / 'versions/11'
        old_cfg = C.document(old['documents']['versions/11/runtime-configuration.json'])
        old_sup_raw = old['documents']['versions/11/supervisor/configuration.json']
        head = {'sequence': 12, 'decision': 'OPERATE', 'sha256': C.sha(r['authorization']), 'authorization': C.document(r['authorization'])}
        wrapper = I.wrapper_bytes(old_cfg['pythonPath'], before)
        with patch.object(I, 'Path', PurePosixPath): unit = I.unit_bytes(root, old_cfg, C.document(old_sup_raw), before)
        disk = {str(root / 'authorization/11.json'): old['authorization'], str(root / 'authorization/12.json'): r['authorization'],
                str(I.UNIT_PATH): unit, '/wrapper': wrapper}
        args = types.SimpleNamespace(install_root=str(root), output_directory='/claim', current_wrapper_sha256=C.sha(wrapper),
            wrapper='/wrapper', lock='/guard', systemctl='/systemctl', systemctl_sha256='a' * 64,
            docker='/docker', docker_sha256='b' * 64, docker_socket='unix:///docker.sock')
        reader = types.SimpleNamespace(hashes={}, verify=lambda: None)
        runtime = types.SimpleNamespace(bound_bytes=lambda _: old_sup_raw)
        with patch.object(I, 'native_switch', return_value=types.SimpleNamespace(custody=lambda p, mode: (disk[str(p)], tuple(range(9))))), \
                patch.object(U.V, 'absolute', side_effect=PurePosixPath), patch.object(U.V, 'private_directory'), \
                patch.object(I, 'Path', PurePosixPath), patch.object(I, 'output_directory'), \
                patch.object(U, 'read_inputs', return_value=(reader, files, inputs['sources'], settings)), \
                patch.object(I, 'authorization', return_value=(None, head)), \
                patch.object(U, 'installed_runtime', return_value=(runtime, old_cfg, b'')), \
                patch.object(U, 'stopped_provider', return_value={}), patch.object(I, 'coordinator_state', return_value={'state': 'QUIESCED'}), \
                patch.object(U.V, 'guard_lock', return_value={'identity': list(range(9))}), \
                patch.object(I, 'systemctl', return_value=('FragmentPath=' + str(I.UNIT_PATH) + '\nNeedDaemonReload=no\nDropInPaths=\nLoadState=loaded\n').encode()), \
                patch.object(U.os.path, 'lexists', return_value=False):
            yield args, inputs, old_sup_raw, r

    def test_full_upgrade_observation_and_denied_foreign_coordinator(self):
        with self.observation_fixture() as (args, inputs, old_sup_raw, r):
            state, result = U.observe(args)
            self.assertEqual((state['versionBefore'], state['versionAfter']), (11, 12))
            self.assertEqual(result, r)
            receipt_raw = inputs['files']['migrationReceipt']
            receipt = C.document(receipt_raw); receipt['planSha256'] = '0' * 64
            inputs['files']['migrationReceipt'] = C.canonical(receipt)
            with self.assertRaisesRegex(RuntimeError, 'MIGRATION_DRIFT'): U.observe(args)
            inputs['files']['migrationReceipt'] = receipt_raw
            inputs['files'].pop('migrationReceipt')
            with self.assertRaisesRegex(RuntimeError, 'EXACT_R3_INPUT_SET_REQUIRED'): U.observe(args)
        inputs, old, _, _ = fixture(); r = composed(inputs, old)
        old_sup = C.document(old['documents']['versions/11/supervisor/configuration.json'])
        new_sup = C.document(r['documents']['versions/12/supervisor/configuration.json'])
        prior = C.document(old['authorization'])
        for version in (11, 13):
            with self.assertRaisesRegex(RuntimeError, 'SHARED_STATE_DRIFT'):
                U.shared_state(version, old_sup, new_sup, inputs['files'], prior)
        for side, field in ((old_sup, 'ownerConfiguration'), (new_sup, 'ownerConfiguration')):
            original = side['coordinator'][field]
            side['coordinator'][field] = {'path': '/foreign/owner', 'sha256': '0' * 64}
            with self.assertRaisesRegex(RuntimeError, 'SHARED_STATE_DRIFT'):
                U.shared_state(12, old_sup, new_sup, inputs['files'], prior)
            side['coordinator'][field] = original


class StartGate(unittest.TestCase):
    @contextmanager
    def observation_fixture(self):
        inputs, old, _, nft_tables = fixture(); r = composed(inputs, old)
        root = PurePosixPath(C.document(inputs['files']['settings'])['installRoot'])
        cfg = C.document(r['documents']['versions/12/runtime-configuration.json'])
        sup = C.document(r['documents']['versions/12/supervisor/configuration.json'])
        owner = C.document(inputs['files']['coordinator'])
        journal = C.document(inputs['files']['coordinationJournal'])
        present = {(f, owner['kernel']['tableName']) for f in ('inet', 'bridge')}
        args = OF.arguments(install_root=str(root), wrapper_sha256=C.sha(b'wrapper'),
                            nft=owner['nftPath'], nft_sha256=owner['nftSha256'])
        payload = C.document(r['authorization'])
        head = {'sha256': C.sha(r['authorization']), 'sequence': 12, 'decision': 'OPERATE', 'authorization': payload}
        epochs = types.SimpleNamespace(boot_id=lambda: 'boot', current=lambda *a: None)
        status = {'schema': 'ouf.semantic-provider-lease-supervisor-status.v1',
                  **OF.observation()['supervisor'], 'authorizationSequence': 12}
        def custody(path, mode):
            return ({sup['statusPath']: C.canonical(status), sup['coordinator']['journalPath']: C.canonical(journal)}.get(str(path), b'wrapper'), ())
        runtime = types.SimpleNamespace(load_configuration=lambda p: (cfg, b'cfg'), verify_files=lambda c: None,
            operation_modules=lambda c: (None, epochs), authorization_head=lambda *a: head,
            bound_bytes=lambda b: inputs['files']['coordinator'] if b == sup['coordinator']['ownerConfiguration'] else C.canonical(sup))
        def docker(args, verb, cid, **kw):
            self.assertEqual(verb, 'inspect', 'denied gate must not submit any lifecycle request')
            return C.canonical({'unused': None}) if cid is None else json.dumps([{'Id': cid,
                'State': {'Status': 'exited', 'Running': False, 'Pid': 0, 'StartedAt': '2026-11-17T00:00:00Z'},
                'RestartCount': 0, 'HostConfig': {'Runtime': 'ouf-semantic-admitted-v2', 'RestartPolicy': {'Name': 'no'}}}]).encode()
        def command(path, digest, argv, timeout):
            if path == args.systemctl: return b'ActiveState=active\nSubState=running\nNRestarts=0\n'
            if argv == ['-j', 'list', 'tables']:
                return C.canonical({'nftables': [{'table': {'family': f, 'name': n}} for f, n in sorted(present)]})
            self.assertEqual(argv[:3], ['-j', 'list', 'table'])
            return C.canonical(nft_tables[argv[3]])
        with patch.object(I, 'native_switch', return_value=types.SimpleNamespace(custody=custody)), \
                patch.object(O.V, 'absolute', side_effect=PurePosixPath), patch.object(O.V, 'private_directory'), \
                patch.object(I, 'output_directory'), patch.object(I, 'compiled', return_value=runtime), \
                patch.object(I, 'wrapper_bytes', return_value=b'wrapper'), \
                patch.object(I, 'wrapper_code_root', return_value=root / 'versions/12'), \
                patch.object(O, 'docker', side_effect=docker), patch.object(O, 'command', side_effect=command), \
                patch.object(O, 'broker_denials', return_value=[]), patch.object(O.VR, 'plan', return_value={}):
            yield args, owner, journal, present, runtime

    def test_real_observer_blocks_apply_before_any_start_or_output(self):
        for blocked in (False, True):
            with self.subTest(blocked=blocked), self.observation_fixture() as (args, owner, journal, tables, runtime):
                plan = O.proposal(args, O.observe(args)); args.plan_sha256 = plan['planSha256']
                if blocked: journal['state'] = 'BLOCKED'
                else: tables.add(('inet', owner['kernel']['tableName'][:-3]))
                with patch.object(I, 'write_once') as write, self.assertRaisesRegex(RuntimeError,
                        'JOURNAL_BLOCKED' if blocked else 'NOT_FINALIZED'):
                    O.apply(args, plan, dict(O.COUNTERS))
                write.assert_not_called()

    def test_read_only_finalize_observer_does_not_require_start_gate(self):
        # Task-65 calls observe without action, including before finalize.
        with self.observation_fixture() as (args, owner, journal, tables, runtime):
            del args.action
            tables.add(('inet', owner['kernel']['tableName'][:-3]))
            self.assertNotIn('leaseKernel', O.observe(args))

    def test_predecessor_missing_successor_and_native_seal(self):
        inputs, _, _, tables = fixture()
        owner = C.document(inputs['files']['coordinator']); journal = C.document(inputs['files']['coordinationJournal'])
        name = owner['kernel']['tableName']; present = {(f, name) for f in ('inet', 'bridge')}
        read = Mock(side_effect=lambda f, n: tables[f])
        self.assertTrue(O.lease_kernel_state(owner, journal, present, read)['predecessorAbsent'])
        for inventory in (present | {('inet', name[:-3])}, present | {('bridge', name[:-3])},
                          present | {(f, name[:-3]) for f in ('inet', 'bridge')}):
            read.reset_mock()
            with self.assertRaisesRegex(RuntimeError, 'NOT_FINALIZED'): O.lease_kernel_state(owner, journal, inventory, read)
            read.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, 'JOURNAL_BLOCKED'):
            O.lease_kernel_state(owner, {**journal, 'state': 'BLOCKED'}, present, read)
        for inventory in (set(), {('inet', name)}, {('bridge', name)}):
            with self.assertRaisesRegex(RuntimeError, 'STRUCTURE_DRIFT'): O.lease_kernel_state(owner, journal, inventory, read)
        tables['inet']['nftables'][1]['table']['handle'] += 1
        with self.assertRaisesRegex(RuntimeError, 'STRUCTURE_DRIFT'): O.lease_kernel_state(owner, journal, present, read)


@unittest.skipUnless(NATIVE, 'requires explicit Linux/root native kernel gate')
class NativeStartGate(unittest.TestCase):
    def test_real_g1_g2_coexistence_finalize_and_seal_in_private_netns(self):
        script = '''
import json, subprocess, sys
from pathlib import Path
sys.path[:0] = [str(Path.cwd()), str(Path.cwd() / 'tests')]
import test_semantic_provider_r3_v12 as T
C, O, K = T.C, T.O, T.K
inputs, old, retained, unused = T.fixture()
owner = C.document(inputs['files']['coordinator'])
journal = C.document(inputs['files']['coordinationJournal'])
prior = C.document(inputs['files']['migrationPlan'])['context']['owner']
def nft(*args, raw=None):
    result = subprocess.run(['/usr/sbin/nft', *args], input=raw, capture_output=True, check=True)
    return json.loads(result.stdout) if '-j' in args else None
def inventory():
    return {(r['table']['family'], r['table']['name']) for r in nft('-j', 'list', 'tables')['nftables'] if 'table' in r}
def read(family, name): return nft('-j', 'list', 'table', family, name)
def denied(code):
    try: O.lease_kernel_state(owner, journal, inventory(), read)
    except RuntimeError as error: assert str(error) == code, str(error)
    else: raise AssertionError('start should have been denied')
assert Path('/proc/self/ns/net').stat().st_ino != Path('/proc/1/ns/net').stat().st_ino
assert not inventory(), 'namespace must be empty'
compiler = C.contract_module(C.sources_v12(inputs['sources'])[C.KERNEL_V2], 'native_g2')
rules = compiler.materialize(prior['kernel'], empty_provider_sets=True)['nftRules']
rules += compiler.materialize(owner['kernel'], empty_provider_sets=True)['nftRules']
nft('-f', '-', raw=rules.encode('ascii'))
name = owner['kernel']['tableName']
tables = {f: read(f, name) for f in ('inet', 'bridge')}
owner['expectedStructureHash'] = K.digest(K.structure(tables))
owner['binding']['leaseStructureHash'] = owner['expectedStructureHash']
denied('R3_LEASE_KERNEL_NOT_FINALIZED')
nft('-f', '-', raw=('delete table inet ' + prior['kernel']['tableName'] + '\\n'
    + 'delete table bridge ' + prior['kernel']['tableName'] + '\\n').encode())
assert O.lease_kernel_state(owner, journal, inventory(), read)['predecessorAbsent']
journal['state'] = 'BLOCKED'
denied('R3_LEASE_KERNEL_JOURNAL_BLOCKED')
journal['state'] = 'QUIESCED'
nft('add', 'chain', 'inet', name, 'unexpected')
denied('R3_LEASE_KERNEL_STRUCTURE_DRIFT')
'''
        result = subprocess.run(['unshare', '--net', '--fork', sys.executable, '-I', '-B', '-c', script],
                                cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__': unittest.main()
