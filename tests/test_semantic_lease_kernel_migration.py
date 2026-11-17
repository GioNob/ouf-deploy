"""Portable D-050 transactions, real contracts with an in-memory effect boundary."""
import copy
from contextlib import contextmanager
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))
from tools.semantic_lease_kernel_migration import migration as M
from tools.semantic_lease_kernel_migration import boot_dispatcher as B
from tools.semantic_lease_kernel_migration import native as N
from test_semantic_lease_kernel_v2 import kernel, m, old


def fixture_tables(config, table_handle=10):
    return {f: {'nftables': [{'metainfo': {'version': 'fixture'}},
        {'table': {'family': f, 'name': config['tableName'], 'handle': table_handle + i}},
        {'set': {'family': f, 'table': config['tableName'], 'name': 'provider_0', 'handle': 1,
                 'type': 'ipv4_addr', 'flags': ['timeout']}},
        {'chain': {'family': f, 'table': config['tableName'], 'name': 'governed', 'handle': 2}},
        {'rule': {'family': f, 'table': config['tableName'], 'chain': 'governed', 'handle': 3,
                  'expr': [{'counter': {'packets': 0, 'bytes': 0}}, {'accept': None}]}}]}
        for i, f in enumerate(('inet', 'bridge'))}


def observation():
    return {'authorization': {'sequence': 1, 'sha256': 'a' * 64, 'decision': 'OPERATE'},
        'configurationSha256': 'b' * 64,
        'candidates': {r: {'cid': r, 'docker': {'Status': 'exited', 'Running': False, 'Pid': 0,
                                             'RestartPolicy': 'no'},
                           'epoch': {'state': 'DELETED', 'live': False, 'epoch': 1}}
                       for r in ('adapter', 'southbound')},
        'supervisor': {'state': 'WAITING', 'authorizationSequence': 1,
                       'unit': {'ActiveState': 'active', 'SubState': 'running'}},
        'lease': {'state': 'QUIESCED', 'leaseAuthorized': False},
        'tables': {r: {'inet': False, 'bridge': False} for r in ('adapter', 'southbound')}}


class Fixture:
    def __init__(self):
        cfg = kernel()
        self.owner = {'kernel': cfg, 'expectedStructureHash': B.digest(B.structure(fixture_tables(cfg))),
                      'binding': {'transactionId': 'c' * 64}, 'journalFile': '/fixture/journal'}
        self.journal = {'state': 'QUIESCED', 'leaseAuthorized': False, 'startAuthorized': False,
                        **self.owner['binding'], 'leaseAddresses': [[]]}
        self.obs = observation()
        self.current = {cfg['tableName']: fixture_tables(cfg)}
        self.files, self.events = {}, []
        self.public = {'guard': 'old-guard', 'docker': 'old-docker', 'pointer': 'old-pointer'}
        self.locked = False
        self.effects = []
        self.fail = None
        self.new = None
        self.head_generation = 1
        self.claimed = False

    def hit(self, name):
        self.effects.append(name)
        if self.fail == name:
            self.fail = None
            raise RuntimeError('INJECTED_FAILURE')

    def observe(self):
        return copy.deepcopy(self.obs)

    def context(self):
        return copy.deepcopy({'owner': self.owner, 'journal': self.journal})

    def authorization(self, owner, phase, observation):
        wanted = 2 if phase == 'finalize' else 1
        B.need(self.head_generation == wanted, 'LEASE_KERNEL_R3_HEAD_KERNEL_MISMATCH')

    def paths(self):
        return {'generationDirectory': '/fixture/g2'}

    def source_hashes(self):
        return {'compiler': 'd' * 64}

    def template(self, cfg):
        return fixture_tables(cfg, 1)

    def tables(self, cfg):
        return copy.deepcopy(self.current.get(cfg['tableName']))

    @contextmanager
    def locks(self):
        B.need(not self.locked, 'OPERATION_IN_PROGRESS')
        self.locked = True
        try:
            yield
        finally:
            self.locked = False

    def claim(self, plan):
        assert self.locked
        B.need(not self.claimed, 'CLAIM_CONSUMED')
        self.claimed = True
        self.save('plan.json', plan)
        self.hit('claim')

    def prepare(self, plan):
        self.hit('prepare')

    def compile(self, cfg):
        m.materialize(cfg, empty_provider_sets=True)
        return ('create', cfg)

    def delete(self, cfg):
        return ('delete', cfg)

    def batch(self, command):
        assert self.locked
        self.hit('nft-before')
        verb, cfg = command
        if verb == 'create':
            self.current[cfg['tableName']] = fixture_tables(cfg, 90)
        else:
            self.current.pop(cfg['tableName'])
        self.hit('nft-after')

    def save(self, name, value):
        B.need(name not in self.files, 'WRITE_ONCE')
        self.hit('save-before-' + name)
        self.files[name] = copy.deepcopy(value)
        self.hit('save-after-' + name)

    def load(self, name):
        return copy.deepcopy(self.files[name])

    def exists(self, name):
        return name in self.files

    def record(self, row):
        self.events.append(copy.deepcopy(row))
        self.hit(row['phase'] + ':' + row['side'])

    def event_exists(self, phase, side):
        return any(e['phase'] == phase and e['side'] == side for e in self.events)

    def stage(self, plan, tables):
        self.hit('stage-before')
        self.new = {**self.owner, 'kernel': plan['destination'],
                    'expectedStructureHash': B.digest(B.structure(tables))}
        self.hit('stage-after')
        return [{'path': k, 'old': v, 'new': 'new-' + k} for k, v in self.public.items()]

    def publication_state(self, entries):
        rows = []
        for e in entries:
            value = self.public[e['path']]
            B.need(value in (e['old'], e['new']), 'FOREIGN_PUBLICATION_PRESERVED')
            rows.append({'state': 'new' if value == e['new'] else 'old'})
        return rows

    def publish(self, entries, restore):
        self.publication_state(entries)
        for e in reversed(entries) if restore else entries:
            self.public[e['path']] = e['old' if restore else 'new']
            self.hit('publish-' + e['path'])
        self.hit('daemon-reload')
        self.hit('loaded-readback')

    def check_journals(self, plan):
        M.quiesced(self.owner, self.journal)

    def new_owner(self):
        return copy.deepcopy(self.new)

    def finalize_claim(self, planned):
        if self.exists('finalize-plan.json'):
            B.need(self.load('finalize-plan.json') == planned, 'CLAIM_CHANGED')
        else:
            self.save('finalize-plan.json', planned)

    def upgrade(self):
        self.head_generation = 2
        self.obs['authorization'] = {'sequence': 2, 'sha256': 'e' * 64, 'decision': 'OPERATE'}
        self.obs['supervisor']['authorizationSequence'] = 2


class MigrationTests(unittest.TestCase):
    def migrated(self):
        io = Fixture()
        p = M.plan(io)
        result = M.apply(io, p, p['planSha256'])
        self.assertEqual(result['status'], 'LEASE_KERNEL_MIGRATED')
        return io, p

    def test_plan_deterministic_and_exact_diff(self):
        io = Fixture()
        p = M.plan(io)
        self.assertEqual(p, M.plan(io))
        self.assertEqual({x['field'] for x in p['difference']}, {'generation', 'providerFlowMatch', 'tableName'})
        self.assertEqual(p['destination']['tableName'], io.owner['kernel']['tableName'] + '_g2')
        self.assertEqual(io.effects, [])

    def test_diff_denies_every_undeclared_change(self):
        old_cfg = kernel()
        target = M.destination(old_cfg, 2)
        for key, value in {'staticFlows': [], 'providerFlows': [], 'existingInterfaces': [],
                           'guardedInterfaces': ['other'], 'unexpected': True, 'tableName': 'other',
                           'providerFlowMatch': 'CURRENT_TUPLE'}.items():
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, 'LEASE_KERNEL_DIFF_NOT_ALLOWED'):
                    M.difference(old_cfg, {**target, key: value})

    def test_unregistered_generation_and_long_name_deny(self):
        with self.assertRaisesRegex(ValueError, 'GENERATION_NOT_SUPPORTED'):
            M.destination(kernel(2), 3)
        with self.assertRaisesRegex(ValueError, 'TABLE_NAME_TOO_LONG'):
            M.destination({**kernel(), 'tableName': 'a' * 32}, 2)

    def test_each_precondition_is_rechecked_before_claim(self):
        changes = [
            lambda io: io.obs['candidates']['adapter']['docker'].update(Running=True),
            lambda io: io.obs['candidates']['southbound']['docker'].update(Pid=1),
            lambda io: io.obs['candidates']['adapter']['docker'].update(RestartPolicy='always'),
            lambda io: io.obs['candidates']['adapter']['epoch'].update(state='STARTED'),
            lambda io: io.obs['candidates']['southbound']['epoch'].update(live=True),
            lambda io: io.obs['candidates']['adapter'].update(epoch=None),
            lambda io: io.obs['supervisor'].update(state='ACTIVE'),
            lambda io: io.obs['lease'].update(leaseAuthorized=True),
            lambda io: io.journal.update(startAuthorized=True),
            lambda io: io.obs['tables']['adapter'].update(inet=True),
            lambda io: setattr(io, 'head_generation', 2),
            lambda io: io.current[io.owner['kernel']['tableName']]['inet']['nftables'][1]['table'].update(handle=100),
            lambda io: io.current.update({M.destination(io.owner['kernel'], 2)['tableName']: fixture_tables(kernel(2))}),
        ]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                io = Fixture()
                p = M.plan(io)
                change(io)
                with self.assertRaises(ValueError):
                    M.apply(io, p, p['planSha256'])
                self.assertEqual(io.effects, [])

    def test_another_operation_denies_without_claim(self):
        io = Fixture()
        p = M.plan(io)
        io.locked = True
        with self.assertRaisesRegex(ValueError, 'OPERATION_IN_PROGRESS'):
            M.apply(io, p, p['planSha256'])
        self.assertFalse(io.claimed)

    def test_full_apply_and_restore_and_idempotence(self):
        io, p = self.migrated()
        self.assertEqual(len(io.current), 2)
        self.assertEqual(B.digest(B.structure(io.tables(io.owner['kernel']))), p['before']['structure'])
        result = M.restore(io, p, p['planSha256'])
        self.assertEqual(result['before'], result['after'])
        self.assertEqual(M.restore(io, p, p['planSha256']), result)
        self.assertEqual(len(io.current), 1)
        self.assertTrue(all(value.startswith('old-') for value in io.public.values()))

    def test_every_intermediate_failure_can_restore(self):
        points = ['claim', 'generation:before', 'prepare', 'generation:after', 'nft-create:before',
            'nft-before', 'nft-after', 'save-before-native-after.json', 'save-after-native-after.json',
            'nft-create:after', 'stage-before', 'stage-after', 'save-before-publication.json',
            'save-after-publication.json', 'publication:before', 'publish-guard', 'publish-docker',
            'publish-pointer', 'daemon-reload', 'loaded-readback', 'publication:after',
            'save-before-receipt.json', 'save-after-receipt.json']
        for point in points:
            with self.subTest(point=point):
                io = Fixture()
                p = M.plan(io)
                io.fail = point
                with self.assertRaisesRegex(RuntimeError, 'INJECTED_FAILURE'):
                    M.apply(io, p, p['planSha256'])
                M.restore(io, p, p['planSha256'])
                self.assertEqual(len(io.current), 1)
                self.assertEqual(B.digest(B.structure(io.tables(io.owner['kernel']))), p['before']['structure'])
                self.assertTrue(all(value.startswith('old-') for value in io.public.values()))

    def test_every_restore_failure_is_resumable(self):
        for point in ('restore-publication:before', 'publish-pointer', 'publish-docker', 'publish-guard',
                      'daemon-reload', 'loaded-readback', 'restore-publication:after', 'restore-nft:before',
                      'nft-before', 'nft-after', 'restore-nft:after', 'save-before-restore-receipt.json',
                      'save-after-restore-receipt.json'):
            with self.subTest(point=point):
                io, p = self.migrated()
                io.fail = point
                with self.assertRaises(RuntimeError):
                    M.restore(io, p, p['planSha256'])
                self.assertEqual(M.restore(io, p, p['planSha256'])['status'], 'LEASE_KERNEL_RESTORED')

    def test_foreign_publication_or_tables_preserved(self):
        for foreign in ('pointer', 'old-handle', 'new-handle', 'elements', 'expressions'):
            with self.subTest(foreign=foreign):
                io, p = self.migrated()
                if foreign == 'pointer':
                    io.public['pointer'] = 'foreign'
                else:
                    cfg = io.owner['kernel'] if foreign == 'old-handle' else p['destination']
                    rows = io.current[cfg['tableName']]['inet']['nftables']
                    if foreign.endswith('handle'):
                        rows[1]['table']['handle'] += 1
                    elif foreign == 'elements':
                        rows[2]['set']['elem'] = ['198.51.100.1']
                    else:
                        rows[4]['rule']['expr'] = [{'drop': None}]
                retained = copy.deepcopy((io.current, io.public))
                with self.assertRaises(ValueError):
                    M.restore(io, p, p['planSha256'])
                self.assertEqual((io.current, io.public), retained)

    def test_digest_tamper_replay_and_auth_change(self):
        io, p = self.migrated()
        with self.assertRaises(ValueError):
            M.apply(io, p, p['planSha256'])
        changed = copy.deepcopy(p)
        changed['destination']['staticFlows'] = []
        with self.assertRaisesRegex(ValueError, 'PLAN_DIGEST_CHANGED'):
            M.restore(io, changed, p['planSha256'])
        io.obs['authorization']['sequence'] = 2
        io.obs['supervisor']['authorizationSequence'] = 2
        with self.assertRaisesRegex(ValueError, 'HEAD_CHANGED_RESTORE_DENIED'):
            M.restore(io, p, p['planSha256'])

    def test_finalize_requires_upgrade_idle_and_published(self):
        io, p = self.migrated()
        with self.assertRaisesRegex(ValueError, 'R3_HEAD_KERNEL_MISMATCH'):
            M.finalize_plan(io, p)
        io.upgrade()
        final = M.finalize_plan(io, p)
        self.assertTrue(final['pointOfNoReturn'])
        io.obs['candidates']['adapter']['epoch']['live'] = True
        with self.assertRaisesRegex(ValueError, 'EPOCH_NOT_TERMINAL'):
            M.finalize(io, p, final, final['planSha256'])
        self.assertFalse(io.exists('finalize-intent.json'))

    def test_finalize_removes_only_old_tables_and_denies_restore(self):
        io, p = self.migrated()
        io.upgrade()
        final = M.finalize_plan(io, p)
        result = M.finalize(io, p, final, final['planSha256'])
        self.assertEqual(result['status'], 'LEASE_KERNEL_FINALIZED')
        self.assertIsNone(io.tables(io.owner['kernel']))
        self.assertIsNotNone(io.tables(p['destination']))
        with self.assertRaisesRegex(ValueError, 'FINALIZE_IRREVERSIBLE'):
            M.restore(io, p, p['planSha256'])

    def test_finalize_failure_resume_before_and_after_irreversible_batch(self):
        for point in ('save-after-finalize-plan.json', 'finalize-nft:before',
                      'save-before-finalize-intent.json', 'save-after-finalize-intent.json',
                      'nft-before', 'nft-after', 'finalize-nft:after',
                      'save-before-finalize-receipt.json', 'save-after-finalize-receipt.json'):
            with self.subTest(point=point):
                io, p = self.migrated()
                io.upgrade()
                final = M.finalize_plan(io, p)
                io.fail = point
                with self.assertRaises(RuntimeError):
                    M.finalize(io, p, final, final['planSha256'])
                self.assertEqual(M.finalize(io, p, final, final['planSha256'])['status'], 'LEASE_KERNEL_FINALIZED')

    def test_native_seal_exactly_matches_historical_projection(self):
        spec = importlib.util.spec_from_file_location('historical_hash65', ROOT /
            'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_nft.py')
        historical = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'tools.materialize_southbound_kernel': old}):
            spec.loader.exec_module(historical)
        raw = fixture_tables(kernel())
        raw['inet']['nftables'][2]['set']['elem'] = ['198.51.100.1']
        self.assertEqual(B.digest(B.structure(raw)), historical.structure_hash(raw))

    def test_boot_command_exact_verification_and_rewrite(self):
        cmd = '/usr/bin/python3 -I -B /root/dispatcher.py --pointer /etc/ouf/pointer --self-sha256 ' + 'a' * 64
        raw = b'[Service]\nExecStart=/old/path\nOther=preserved\n'
        new = N.rewrite(raw, 'ExecStart', cmd)
        self.assertIn(b'Other=preserved\n', new)
        self.assertEqual(N.boot_command(new, 'ExecStart'), cmd)
        loaded = {'guard': {'ExecStart': '{ path=/usr/bin/python3 ; argv[]=' + cmd + ' ; ignore_errors=no ; }'}}
        N.Native.verify_commands(loaded, {'guard': cmd})
        for wrong in (cmd + ' --extra', '/bin/false ' + cmd):
            with self.assertRaisesRegex(ValueError, 'LOADED_BOOT_COMMAND_DRIFT'):
                N.Native.verify_commands(loaded, {'guard': wrong})
        with self.assertRaises(ValueError):
            N.rewrite(raw + b'ExecStart=/extra\n', 'ExecStart', cmd)

    def test_boot_sandbox_conversion_once_and_future_parent_constraint(self):
        io = N.Native.__new__(N.Native)
        io.generation = Path('/etc/ouf/generations/g2')
        io.dispatcher = Path('/etc/ouf/dispatcher.py')
        io.dispatch_command = lambda: '/usr/bin/python3.12 -I -B /etc/ouf/dispatcher.py --pointer /etc/ouf/pointer --self-sha256 ' + 'a' * 64
        ctx = {'units': {'guard': '[Service]\nExecStart=/old\n', 'docker': '[Service]\nExecStartPre=/old\n'},
               'loaded': {'guard': {'ProtectSystem': 'strict', 'ReadWritePaths': '/var/lib/ouf',
                                    'InaccessiblePaths': '', 'ReadOnlyPaths': ''}}}
        first = io.proposed_units(ctx)
        self.assertIn('ReadWritePaths=' + str(io.generation.parent), first['guard'])
        self.assertNotIn('ReadWritePaths', first['docker'])
        next_context = copy.deepcopy(ctx)
        next_context['units'] = first
        next_context['loaded']['guard']['ReadWritePaths'] += ' ' + str(io.generation.parent).replace('\\', '/')
        self.assertEqual(io.proposed_units(next_context), first)
        next_context['loaded']['guard']['ReadWritePaths'] = '/different/root'
        with self.assertRaisesRegex(ValueError, 'BOOT_GENERATION_ROOT_CHANGED'):
            io.proposed_units(next_context)
        ctx['loaded']['guard']['ReadOnlyPaths'] = '/etc/ouf'
        with self.assertRaisesRegex(ValueError, 'BOOT_GENERATION_PATH_INACCESSIBLE'):
            io.proposed_units(ctx)

    def test_docker_other_precommands_preserved_exactly(self):
        command = '/usr/bin/python3 -I -B /etc/ouf/dispatcher.py'
        raw = '{ path=/sbin/modprobe ; argv[]=/sbin/modprobe overlay ; } { path=/usr/bin/python3 ; argv[]=' + command + ' ; }'
        loaded = {'docker': {'ExecStartPre': raw}}
        N.Native.verify_commands(loaded, {'docker': command}, {'docker': ['/sbin/modprobe overlay', command]})
        with self.assertRaisesRegex(ValueError, 'LOADED_BOOT_COMMAND_DRIFT'):
            N.Native.verify_commands(loaded, {'docker': command}, {'docker': [command]})


class NativeFilesPortableTests(unittest.TestCase):
    """Exercise the REAL adapter's profile builder/CAS path with portable custody.

    Only Linux mode/uid/fsync primitives are substituted. Native CI separately
    tests those primitives under root; no fixture writes /etc or systemd.
    """
    def test_real_staging_and_partial_publication_restore(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            io = N.Native.__new__(N.Native)
            io.work, io.generation = root / 'claim', root / 'g2'
            io.work.mkdir(); io.generation.mkdir()
            io.dispatcher = root / 'dispatcher.py'
            io.dispatch_command = lambda: '/usr/bin/python3.12 -I -B /root/dispatcher.py --pointer /etc/ouf/pointer --self-sha256 ' + 'a' * 64
            io.manifest = {'executables': {'python': {'path': '/usr/bin/python3.12'}},
                           'owner': {'path': str(root / 'old-owner.json')}, 'units': {}}
            io.args = types.SimpleNamespace()
            io.systemctl = {'path': '/usr/bin/systemctl', 'sha256': '9' * 64}
            fixture = Fixture()
            io.owner = {**fixture.owner, 'sourceHashes': {}, 'nftPath': '/usr/sbin/nft',
                        'nftSha256': 'f' * 64, 'commonLockFile': '/root/common.lock'}
            io.boot = {'kernel': io.owner['kernel'], 'lockFile': '/root/common.lock', 'nftPath': '/usr/sbin/nft',
                       'journalFile': '/root/boot-journal.json'}
            io.profile = {'sourceHashes': {}, 'bootGuardFile': '/root/legacy-boot.py'}
            io.original_sources = {'tools/materialize_southbound_kernel.py': b'# preserved legacy compiler\n'}
            units = {'guard': str(root / 'guard.service'), 'docker': str(root / 'docker.conf')}
            pointer = str(root / 'pointer.json')
            old_units = {'guard': '[Service]\nExecStart=/legacy/guard\nPreserved=true\n',
                         'docker': '[Service]\nExecStartPre=/legacy/guard\nPreserved=true\n'}
            for key, path in units.items():
                Path(path).write_bytes(old_units[key].encode('ascii'))
                io.manifest['units'][key] = {'path': path, 'sha256': B.sha(old_units[key].encode('ascii'))}
            Path(pointer).write_bytes(b'{"old":true}')
            io.manifest['pointer'] = {'path': pointer, 'sha256': B.sha(b'{"old":true}')}
            planned = M.plan(fixture)
            planned['context'].update(units=old_units, pointerRaw='{"old":true}')
            baseline = {key: {'MainPID': '42', 'FragmentPath': path, 'DropInPaths': '',
                             'fileHashes': {path: B.sha(old_units[key].encode('ascii'))},
                             N.DIRECTIVES[key]: '{ path=/legacy/guard ; argv[]=/legacy/guard ; }'}
                        for key, path in units.items()}
            planned['context']['loaded'] = baseline

            def read(path, expected=None):
                raw = Path(path).read_bytes()
                B.need(expected is None or B.sha(raw) == expected, 'SEALED_FILE_CHANGED')
                return raw

            def create(path, raw):
                with Path(path).open('xb') as stream:
                    stream.write(raw)

            def cas(path, before, after):
                B.need(read(path) == before, 'FOREIGN_PUBLICATION_PRESERVED')
                Path(path).write_bytes(after)

            def loaded():
                value = copy.deepcopy(baseline)
                for key, path in units.items():
                    cmd = N.boot_command(read(path), N.DIRECTIVES[key])
                    value[key][N.DIRECTIVES[key]] = '{ path=/usr/bin/python3.12 ; argv[]=' + cmd + ' ; }'
                    value[key]['fileHashes'][path] = B.sha(read(path))
                return value

            with patch.object(B, 'private', side_effect=read), patch.object(B, 'write_once', side_effect=create), \
                 patch.object(B, 'cas', side_effect=cas), patch.object(B, 'command', return_value=b'') as command, \
                 patch.object(N, 'UNITS', units), patch.object(N, 'POINTER', pointer):
                io.save('plan.json', planned)
                target = fixture_tables(planned['destination'], 90)
                entries = io.stage(planned, target)
                new_owner = io.new_owner()
                self.assertEqual(new_owner['kernel'], planned['destination'])
                self.assertEqual(new_owner['binding']['leaseStructureHash'], B.digest(B.structure(target)))
                self.assertIn('tools/materialize_southbound_lease_refresh_v2.py', new_owner['sourceHashes'])
                journal = B.document(read(new_owner['journalFile']))
                M.quiesced(new_owner, journal)
                io.save('publication.json', entries)
                io.loaded = loaded
                io.publish(entries, restore=False)
                self.assertTrue(all(row['state'] == 'new' for row in io.publication_state(entries)))
                io.publish(entries, restore=True)
                self.assertEqual(read(pointer), b'{"old":true}')
                for key, path in units.items():
                    self.assertEqual(read(path), old_units[key].encode('ascii'))
                # Simulate the reverse partial: pointer new while units old.
                Path(pointer).write_bytes(entries[-1]['new'].encode('ascii'))
                io.publish(entries, restore=True)
                self.assertEqual(read(pointer), b'{"old":true}')
                Path(units['docker']).write_bytes(b'foreign')
                before = read(pointer)
                with self.assertRaisesRegex(ValueError, 'FOREIGN_PUBLICATION_PRESERVED'):
                    io.publish(entries, restore=True)
                self.assertEqual(read(pointer), before)
                self.assertTrue(all(call.args[1] == ['daemon-reload'] for call in command.call_args_list))


if __name__ == '__main__':
    unittest.main(verbosity=2)
