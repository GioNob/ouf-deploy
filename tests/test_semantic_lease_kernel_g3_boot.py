"""Portable A3 boot and reconciliation transactions, synthetic authority and kernel."""
from contextlib import ExitStack, contextmanager
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.semantic_lease_kernel_migration import boot_dispatcher as B, boot_runner_v3 as runner
from tools.semantic_lease_kernel_migration import g3_contract as g, g3_journal as J, g3_reconcile as R

HEAD = 'a' * 64
OLD = '00000000-0000-4000-8000-000000000001'
NOW = '00000000-0000-4000-8000-000000000002'
FIXTURES = ROOT / 'tests/fixtures'
MODULES = Path(runner.__file__).parent


def empty_pair():
    tables = json.loads((FIXTURES / 'lease-kernel-g3-nft-1.1.3-synthetic.json').read_bytes())
    for doc in tables.values():
        next(r['set'] for r in doc['nftables'] if 'set' in r).pop('elem')
    return tables


def stage(root, api, kernel, nft, reference, previous=OLD):
    """Stage an isolated test receipt with the real closure file layout."""
    for sub in ('source', 'source/tools', 'source/scripts', 'receipts', 'seals', 'issuer'):
        (root / sub).mkdir(mode=0o700)
    closure = {}

    def put(name, raw):
        api.write_once(root / name, raw)
        return api.sha(raw)

    for name in ('g3_contract', 'g3_journal', 'boot_runner_v3'):
        rel = 'source/tools/' + name + '.py'
        closure[rel] = put(rel, (MODULES / (name + '.py')).read_bytes())
    compilers = ROOT / 'tools/semantic_cohort_admission/cohort-draft'
    for name in ('materialize_southbound_kernel', 'materialize_southbound_kernel_v2'):
        rel = 'tools/' + name + '.py'
        closure['source/' + rel] = put('source/' + rel, (compilers / rel).read_bytes())
    profile = g.listing_profile(reference['inet']['nftables'][0])
    footprint = g.policy_footprint(reference, profile)
    for name in ('adapter.lock', 'southbound.lock', 'common.lock'):
        put(name, b'')
    owner = dict(generation=3, kernel=kernel, renewalMarginSeconds=7, tickSeconds=5, nftPath=nft['path'], nftSha256=nft['sha256'],
                 nftProfile=profile, journalFile=str(root / 'journal'), commonLockFile=str(root / 'common.lock'),
                 receiptDirectory=str(root / 'receipts'), sealDirectory=str(root / 'seals'),
                 authorizationDirectory=str(root / 'issuer'),
                 reconcileObserver={'path': '/fixture/observer', 'sha256': 'd' * 64},
                 operationLockFiles=[str(root / n) for n in ('adapter.lock', 'southbound.lock')],
                 cohortCgroups={role: '/sys/fs/cgroup/' + cid * 64 for role, cid
                                in (('adapter', 'a'), ('southbound', 'b'))})
    owner_hash = put('owner', B.canonical(owner))
    boot = dict(kernel=kernel, nftPath=nft['path'], lockFile=owner['commonLockFile'], head=HEAD,
                expectedFootprint=footprint, projection=g.PROJECTION)
    profile_doc = dict(coordinatedConfiguration=str(root / 'owner'), coordinatedConfigurationHash=owner_hash,
                       bootConfiguration=str(root / 'boot'), bootConfigurationHash=put('boot', B.canonical(boot)))
    receipt = dict(schema='ouf.semantic-lease-kernel-generation.v1', generation=3, directory=str(root),
                   runner='source/tools/boot_runner_v3.py', closure=closure, bootProfile=dict(
                       path=str(root / 'profile'), sha256=put('profile', B.canonical(profile_doc))))
    pointer = dict(schema='ouf.semantic-coordinated-boot-pointer.v1', receiptFile=str(root / 'generation'),
                   receiptHash=put('generation', B.canonical(receipt)), observerFile=str(root / 'dispatcher'),
                   observerHash=put('dispatcher', Path(B.__file__).read_bytes()))
    put('pointer', B.canonical(pointer))
    put('journal', B.canonical(dict(schema=g.JOURNAL, head=HEAD, owner=owner_hash, generation=3,
                                    bootId=previous, state='LEASE_READY', leaseAuthorized=True,
                                    startAuthorized=False)))
    return receipt, dict(head=HEAD, owner=owner_hash, generation=3, decision='OPERATE',
                         projection=g.PROJECTION, footprint=footprint, cohortStopped=True,
                         epochsTerminal=True, supervisor='WAITING')


class Cut(BaseException):
    pass


class PublicationTrace:
    """Cut on either side of a filesystem or nft publication on a fresh fixture."""

    def __init__(self, cut=None):
        self.cut = cut
        self.events = []

    @contextmanager
    def point(self, action, target):
        name = Path(target).name
        for prefix in ('.boot-', '.guard-', '.lease-kernel-'):
            if name.startswith(prefix):
                name = prefix + '*'
                break
        def visit(side):
            event = (action, name, side)
            self.events.append(event)
            if event == self.cut:
                raise Cut(event)

        visit('before')
        yield
        visit('after')

    @contextmanager
    def instrument(self, api):
        def wrap(fn, action, target_arg):
            def traced(*args, **kwargs):
                with self.point(action, args[target_arg]):
                    return fn(*args, **kwargs)
            return traced

        def write_once(path, raw):
            # Split O_EXCL creation from complete bytes visible before file fsync.
            with ExitStack() as handles:
                with self.point('create', path):
                    stream = handles.enter_context(path.open('xb'))
                with self.point('write', path):
                    stream.write(raw)
                    stream.flush()
                os.fsync(stream.fileno())
            api.sync(path.parent)

        command = api.command

        def nft(*args):
            with self.point('batch', 'nft'):
                return command(*args)

        with ExitStack() as patches:
            def replace(obj, name, value):
                patches.enter_context(patch.object(obj, name, value))

            replace(Path, 'mkdir', wrap(Path.mkdir, 'mkdir', 0))
            replace(runner, '_rename_exclusive', wrap(runner._rename_exclusive, 'rename', 1))
            replace(os, 'replace', wrap(os.replace, 'replace', 1))
            replace(api, 'command', nft)
            replace(api, 'write_once', write_once)
            # Exercise the dispatcher's actual CAS tempfile, recheck and replace.
            replace(B, 'safe', Path)
            replace(B, 'private', api.private)
            replace(B, 'sync', api.sync)
            replace(B, 'write_once', write_once)
            replace(api, 'cas', B.cas)
            yield


class Fake:
    canonical, sha, digest, document, need = map(staticmethod, (B.canonical, B.sha, B.digest, B.document, B.need))
    stable, structure, empty = map(staticmethod, (B.stable, B.structure, B.empty))

    def __init__(self, tables):
        self.current = None
        self.template = tables
        self.nft_writes = 0
        self.held = []
        self.cut = None

    def after(self, name):
        if self.cut == name:
            self.cut = None
            raise Cut(name)

    @contextmanager
    def lock(self, path):
        self.held.append(Path(path).name)
        try:
            yield
        finally:
            self.held.pop()

    directory_lock = lock

    def sync(self, path):
        pass

    def private(self, path, expected=None):
        raw = Path(path).read_bytes()
        self.need(expected is None or self.sha(raw) == expected, 'SEALED_FILE_CHANGED')
        return raw

    def write_once(self, path, raw):
        with Path(path).open('xb') as stream:
            stream.write(raw)
        self.after(Path(path).name)

    def cas(self, path, before, after):
        self.need(self.private(path) == before, 'FOREIGN_PUBLICATION_PRESERVED')
        self.after('before-cas')
        Path(path).write_bytes(after)
        self.after('after-cas')

    def sealed_receipt(self, path):
        p = self.document(self.private(path))
        return p, self.document(self.private(p['receiptFile'], p['receiptHash']))

    def tables(self, nft, name):
        if self.current is not None:
            self.need(self.current.keys() == {'bridge', 'inet'}, 'PARTIAL_TABLE_PAIR_PRESERVED')
        return copy.deepcopy(self.current)

    def compiler(self, root, sources):
        self.private(root / 'tools/materialize_southbound_kernel_v2.py',
                     sources['tools/materialize_southbound_kernel_v2.py'])
        return SimpleNamespace(materialize=lambda kernel, empty_provider_sets:
                               {'nftRules': 'empty'} if empty_provider_sets else {})

    def command(self, nft, argv, raw):
        assert argv == ['-f', '-'] and raw == b'empty' and self.current is None
        self.nft_writes += 1
        self.current = copy.deepcopy(self.template)
        self.after('nft')


class Boot(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(temp.cleanup)
        self.prepare(Path(temp.name))
        self.patch(J, 'current_boot_id', lambda: NOW)
        self.patch(J, 'private_directory', lambda api, path: api.need(path.is_dir(), 'G3_PRIVATE_DIRECTORY'))
        # Execute the same pinned module loader as the standalone dispatcher;
        # replace only kernel/custody observations on this non-root test platform.
        self.sealed = runner._journal_module(self.receipt, self.api)
        self.sealed.current_boot_id = J.current_boot_id
        self.sealed.private_directory = J.private_directory
        self.sealed.cohort_empty = lambda owner, api: api.need(self.live['cohortStopped'], 'G3_COHORT')
        self.patch(runner, '_journal_module', lambda receipt, api: self.sealed)

    def prepare(self, root):
        self.root = root
        self.api = Fake(empty_pair())
        self.receipt, self.live = stage(root, self.api, {'tableName': 'sample'},
                                        {'path': '/fixture/nft', 'sha256': HEAD}, self.api.template)
        self.live['bootId'] = NOW
        self.pointer = root / 'pointer'
        self.archive = root / 'receipts' / NOW
        self.seal = root / 'seals' / (NOW + '.json')
        self.previous = self.api.private(root / 'journal')

    def patch(self, obj, attr, value):
        p = patch.object(obj, attr, value)
        p.start()
        self.addCleanup(p.stop)

    def boot(self):
        with self.api.lock(self.root / 'common.lock'):
            runner.run(self.receipt, self.api)

    def journal(self):
        return B.document(self.api.private(self.root / 'journal'))

    def observe(self, state):
        self.assertEqual(self.api.held, ['adapter.lock', 'southbound.lock', 'issuer', 'common.lock'])
        return self.live.copy()

    def plan(self):
        return R.plan(self.pointer, self.observe, self.api)

    def apply(self, digest):
        return R.apply(self.pointer, digest, self.observe, self.api)

    def snapshot(self):
        return {p.relative_to(self.root): p.read_bytes() if p.is_file() else None
                for p in self.root.rglob('*')}

    def assert_state(self, state):
        value = self.journal()
        self.assertEqual((value['bootId'], value['state']), (NOW, state))
        self.assertIs(value['leaseAuthorized'], False)
        self.assertIs(value['startAuthorized'], False)

    def sweep(self, points, scenario):
        events = [(*point, side) for point in points for side in ('before', 'after')]
        for cut in [None, *events]:
            with self.subTest(cut=cut), tempfile.TemporaryDirectory(dir=ROOT) as temp:
                self.prepare(Path(temp))
                trace = PublicationTrace(cut)
                scenario(trace)
                expected = events if cut is None else events[:events.index(cut) + 1]
                self.assertEqual(trace.events, expected)

    def test_a3_15_sweep_boot_publications(self):
        for rebuild in (True, False):
            points = [('mkdir', '.boot-*'), ('create', 'previous.json'), ('write', 'previous.json'),
                      ('create', 'claim.json'), ('write', 'claim.json'), ('rename', NOW)]
            if rebuild:
                points.append(('batch', 'nft'))
            points += [('create', '.guard-*'), ('write', '.guard-*'), ('rename', 'guard.json'),
                       ('create', '.lease-kernel-*'), ('write', '.lease-kernel-*'), ('replace', 'journal')]

            def scenario(trace):
                if not rebuild:
                    self.api.current = self.api.template
                with trace.instrument(self.api):
                    if trace.cut:
                        with self.assertRaises(Cut):
                            self.boot()
                    else:
                        self.boot()
                with PublicationTrace().instrument(self.api):
                    self.boot()
                    self.boot()
                self.assert_state('BLOCKED')
                self.assertEqual(self.api.nft_writes, int(rebuild))
                self.assertEqual((self.archive / 'previous.json').read_bytes(), self.previous)

            with self.subTest(rebuild=rebuild):
                self.sweep(points, scenario)

    def test_a3_18_sweep_apply_publications(self):
        seal = self.seal.name
        points = [('mkdir', 'reconcile'), ('create', 'plan.json'), ('write', 'plan.json'),
                  ('create', 'seal-intent.json'), ('write', 'seal-intent.json'),
                  ('create', seal), ('write', seal), ('create', '.lease-kernel-*'),
                  ('write', '.lease-kernel-*'), ('replace', 'journal'),
                  ('create', 'receipt.json'), ('write', 'receipt.json')]
        # A reserved directory without a complete plan, unmatched intent, or
        # empty public evidence must be preserved for inspection.
        held = {
            ('mkdir', 'reconcile', 'after'): FileNotFoundError,
            ('create', 'plan.json', 'before'): FileNotFoundError,
            ('create', 'plan.json', 'after'): 'G3_PLAN_DRIFT',
            ('write', 'plan.json', 'before'): 'G3_PLAN_DRIFT',
            ('create', 'seal-intent.json', 'after'): g.SEAL_DRIFT,
            ('write', 'seal-intent.json', 'before'): g.SEAL_DRIFT,
            ('write', 'seal-intent.json', 'after'): g.SEAL_DRIFT,
            ('create', seal, 'before'): g.SEAL_DRIFT,
            ('create', seal, 'after'): g.SEAL_DRIFT,
            ('write', seal, 'before'): g.SEAL_DRIFT,
            ('create', 'receipt.json', 'after'): g.BINDING,
            ('write', 'receipt.json', 'before'): g.BINDING,
        }

        def scenario(trace):
            self.boot()
            digest = self.plan()['planSha256']
            with trace.instrument(self.api):
                if trace.cut:
                    with self.assertRaises(Cut):
                        self.apply(digest)
                else:
                    self.apply(digest)
            if trace.cut in held:
                reason = held[trace.cut]
                before = self.snapshot()
                for retry in (self.plan, lambda: self.apply(digest)):
                    error = (self.assertRaisesRegex(ValueError, '^' + reason + '$')
                             if isinstance(reason, str) else self.assertRaises(reason))
                    with error:
                        retry()
                self.assertEqual(self.snapshot(), before)
                self.assert_state('QUIESCED' if trace.cut[1] == 'receipt.json' else 'BLOCKED')
            else:
                self.assertEqual(self.plan()['planSha256'], digest)
                with PublicationTrace().instrument(self.api):
                    done = self.apply(digest)
                    self.assertEqual(self.apply(digest), done)
                    self.boot()
                self.assert_state('QUIESCED')
                self.assertEqual(done['planSha256'], digest)
                self.assertEqual(done['journalSha256'], B.digest(self.journal()))
                self.assertEqual(done['sealSha256'], B.sha(self.seal.read_bytes()))
                self.assertEqual((self.archive / 'reconcile/receipt.json').read_bytes(), B.canonical(done))
            self.assertEqual(self.api.nft_writes, 1)

        self.sweep(points, scenario)

    def test_a3_12_rebuild_double_guard_and_read_only_plan(self):
        self.boot()
        self.assert_state('BLOCKED')
        self.assertEqual((self.archive / 'previous.json').read_bytes(), self.previous)
        before = self.snapshot()
        self.boot()
        digest = self.plan()['planSha256']
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.api.nft_writes, 1)
        receipt = self.apply(digest)
        self.assert_state('QUIESCED')
        after = self.snapshot()
        self.boot()
        self.assertEqual(self.plan()['planSha256'], digest)
        self.assertEqual(self.apply(digest), receipt)
        self.assertEqual(after, self.snapshot())

    def test_a3_13_present_pair_from_previous_quiescence_or_active(self):
        self.api.current = self.api.template
        self.boot()
        self.assert_state('BLOCKED')
        self.assertEqual(self.api.nft_writes, 0)

    def test_a3_13_old_quiescent_still_blocks(self):
        old = {**self.journal(), 'state': 'QUIESCED', 'leaseAuthorized': False}
        (self.root / 'journal').write_bytes(B.canonical(old))
        self.boot()
        self.assert_state('BLOCKED')

    def test_a3_13_migration_seal_on_current_quiescent_boot(self):
        self.api.current = self.api.template
        quiet = {**self.journal(), 'bootId': NOW, 'state': 'QUIESCED', 'leaseAuthorized': False}
        (self.root / 'journal').write_bytes(B.canonical(quiet))
        profile = g.listing_profile(self.api.current['inet']['nftables'][0])
        raw = B.canonical(g.local_seal(HEAD, self.live['owner'], 3, NOW, self.api.current, profile))
        self.api.write_once(self.seal, raw)
        self.receipt['initialSeal'] = 'initial.json'
        self.receipt['closure']['initial.json'] = B.sha(raw)
        snapshot = self.snapshot()
        self.boot()
        self.assertEqual(snapshot, self.snapshot())
        self.receipt['closure']['initial.json'] = HEAD
        with self.assertRaisesRegex(ValueError, g.BINDING):
            self.boot()

    def test_a3_14_deny_before_effect(self):
        for fields in ({'bootId': NOW}, {'bootId': 'invalid'}, {'owner': HEAD}, {'startAuthorized': True}):
            (self.root / 'journal').write_bytes(B.canonical({**B.document(self.previous), **fields}))
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.boot()
            self.assertFalse(self.archive.exists())
            self.assertEqual(self.api.nft_writes, 0)
        (self.root / 'journal').write_bytes(self.previous)
        self.live['cohortStopped'] = False
        with self.assertRaisesRegex(ValueError, 'G3_COHORT'):
            self.boot()
        self.assertFalse(self.archive.exists())

    def test_a3_14_cgroup_observation(self):
        owner = {'cohortCgroups': {'adapter': '/sys/fs/cgroup/' + 'a' * 64,
                                   'southbound': '/sys/fs/cgroup/docker-' + 'b' * 64 + '.scope'}}
        api = SimpleNamespace(need=B.need, safe=Path)
        with patch.object(Path, 'read_bytes', return_value=b'pids memory'), patch.object(
                Path, 'read_text', return_value='populated 0\nfrozen 0\n') as events:
            J.cohort_empty(owner, api)
            self.assertEqual(events.call_count, 2)
            events.return_value = 'populated 1\n'
            with self.assertRaisesRegex(ValueError, 'G3_COHORT'):
                J.cohort_empty(owner, api)
        with patch.object(Path, 'read_bytes', return_value=b'pids'), patch.object(
                Path, 'read_text', side_effect=FileNotFoundError), patch.object(
                Path, 'stat', side_effect=FileNotFoundError) as leaf:
            J.cohort_empty(owner, api)
            leaf.side_effect = None
            with self.assertRaises(FileNotFoundError):
                J.cohort_empty(owner, api)
        with patch.object(Path, 'read_bytes', side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                J.cohort_empty(owner, api)

    def test_a3_15_crash_after_copy_before_claim(self):
        self.api.cut = 'previous.json'
        with self.assertRaises(Cut):
            self.boot()
        staged_copy, = self.archive.parent.glob('.boot-*/previous.json')
        self.assertEqual(staged_copy.read_bytes(), self.previous)
        self.assertFalse(self.archive.exists())
        self.assertEqual((self.root / 'journal').read_bytes(), self.previous)
        self.assertEqual(self.api.nft_writes, 0)
        self.boot()
        self.assert_state('BLOCKED')
        self.assertEqual((self.archive / 'previous.json').read_bytes(), self.previous)
        self.assertEqual(staged_copy.read_bytes(), self.previous)
        self.assertEqual(self.api.nft_writes, 1)

    def test_a3_15_crash_after_claim_directory_rename(self):
        def interrupt_sync(path):
            if path == self.archive.parent and self.archive.exists():
                raise Cut('before parent fsync')

        with patch.object(self.api, 'sync', interrupt_sync), self.assertRaises(Cut):
            self.boot()
        claim = (self.archive / 'claim.json').read_bytes()
        self.assertEqual((self.archive / 'previous.json').read_bytes(), self.previous)
        self.assertEqual(self.api.nft_writes, 0)
        self.boot()
        self.assert_state('BLOCKED')
        self.assertEqual((self.archive / 'claim.json').read_bytes(), claim)
        self.assertEqual(self.api.nft_writes, 1)

    def test_a3_15_crash_after_nft_and_before_cas(self):
        for cut in ('nft', 'before-cas'):
            self.api.cut = cut
            with self.assertRaises(Cut):
                self.boot()
            self.assertEqual(self.previous, (self.root / 'journal').read_bytes())
        self.boot()
        self.assert_state('BLOCKED')
        self.assertEqual(self.api.nft_writes, 1)

    def test_a3_15_crash_during_guard_write(self):
        final = self.archive / 'guard.json'
        write_once = self.api.write_once

        def partial_write(path, raw):
            if not self.api.nft_writes:
                return write_once(path, raw)
            partial = raw[:len(raw) // 2]
            with path.open('xb') as stream:
                stream.write(partial)
            raise Cut('partial guard')

        with patch.object(self.api, 'write_once', partial_write), self.assertRaises(Cut):
            self.boot()
        self.assertFalse(final.exists())
        self.assertEqual((self.root / 'journal').read_bytes(), self.previous)
        self.boot()
        self.assert_state('BLOCKED')
        self.assertEqual(self.api.nft_writes, 1)

    def test_a3_15_crash_after_guard_rename_before_directory_sync(self):
        final = self.archive / 'guard.json'

        def interrupt_sync(directory):
            if directory == self.archive and final.exists():
                raise Cut('before directory fsync')

        with patch.object(self.api, 'sync', interrupt_sync), self.assertRaises(Cut):
            self.boot()
        published = final.read_bytes()
        self.assertEqual(self.previous, (self.root / 'journal').read_bytes())
        with patch.object(self.api, 'sync', wraps=self.api.sync) as sync:
            self.boot()
            self.assertEqual([call.args[0] for call in sync.call_args_list],
                             [self.archive.parent, self.archive])
        self.assert_state('BLOCKED')
        self.assertEqual(final.read_bytes(), published)
        self.assertEqual(self.api.nft_writes, 1)

    def test_a3_15_preserve_existing_guard_at_publication(self):
        final = self.archive / 'guard.json'
        foreign = b'{}'
        rename = runner._rename_exclusive

        def publish_after_collision(staged, target):
            if target == final:
                self.api.write_once(final, foreign)
            rename(staged, target)

        with patch.object(runner, '_rename_exclusive', publish_after_collision), self.assertRaises(FileExistsError):
            self.boot()
        self.assertEqual(final.read_bytes(), foreign)
        self.assertEqual((self.root / 'journal').read_bytes(), self.previous)
        self.assertEqual(self.api.nft_writes, 1)

    def test_a3_16_partial_pair(self):
        self.api.current = {'inet': self.api.template['inet']}
        with self.assertRaisesRegex(ValueError, 'PARTIAL_TABLE_PAIR'):
            self.boot()
        staged_copy, = self.archive.parent.glob('.boot-*/previous.json')
        self.assertEqual(self.previous, staged_copy.read_bytes())
        self.assertFalse(self.archive.exists())
        self.assertEqual(self.api.nft_writes, 0)
        self.api.current = self.api.template
        self.boot()
        self.assert_state('BLOCKED')
        self.assertEqual(self.api.nft_writes, 0)

    def test_a3_16_populated_pair(self):
        self.api.current = json.loads((FIXTURES / 'lease-kernel-g3-nft-1.1.3-synthetic.json').read_bytes())
        with self.assertRaisesRegex(ValueError, g.SETS_NOT_EMPTY):
            self.boot()
        self.assertEqual(self.previous, (self.root / 'journal').read_bytes())

    def test_a3_16_signed_footprint_at_boot(self):
        self.api.current = self.api.template
        self.api.current['bridge']['nftables'][-1]['rule']['expr'] = [{'accept': None}]
        with self.assertRaisesRegex(ValueError, g.POLICY_DRIFT):
            self.boot()
        self.assertEqual(self.previous, (self.root / 'journal').read_bytes())

    def test_a3_17_observation_drift_and_plan_digest(self):
        self.boot()
        digest = self.plan()['planSha256']
        before = self.snapshot()
        for key, value in [('decision', 'REVOKED'), ('head', 'b' * 64), ('owner', HEAD),
                           ('epochsTerminal', False), ('supervisor', 'ACTIVE'), ('cohortStopped', 1)]:
            with self.subTest(key=key), patch.dict(self.live, {key: value}), self.assertRaises(ValueError):
                self.apply(digest)
        with self.assertRaisesRegex(ValueError, 'G3_PLAN_DRIFT'):
            self.apply('0' * 64)
        self.assertEqual(self.snapshot(), before)

    def test_a3_17_pinned_observer_under_locks(self):
        self.boot()
        def command(binding, args):
            self.assertEqual(binding, {'path': '/fixture/observer', 'sha256': 'd' * 64})
            self.assertEqual(args, ['observe', HEAD])
            return B.canonical(self.observe(None))
        self.patch(self.api, 'command', command)
        planned = R.plan(self.pointer, api=self.api)
        R.apply(self.pointer, planned['planSha256'], api=self.api)
        self.assert_state('QUIESCED')

    def test_a3_17_replaced_or_absent_pair_after_guard(self):
        self.boot()
        digest = self.plan()['planSha256']
        self.api.current['inet']['nftables'][1]['table']['handle'] += 99
        for effect in (self.boot, self.plan, lambda: self.apply(digest)):
            with self.assertRaisesRegex(ValueError, g.SEAL_DRIFT):
                effect()
        self.api.current = None
        with self.assertRaises(ValueError):
            self.boot()
        self.assertEqual(self.api.nft_writes, 1)

    def test_a3_18_resume_after_plan_seal_journal_and_final_receipt(self):
        self.boot()
        digest = self.plan()['planSha256']
        for cut in ('plan.json', self.seal.name, 'after-cas', 'receipt.json'):
            self.api.cut = cut
            with self.subTest(cut=cut), self.assertRaises(Cut):
                self.apply(self.plan()['planSha256'])
            self.assertEqual(self.plan()['planSha256'], digest)
        self.apply(digest)
        self.assert_state('QUIESCED')

    def test_a3_15_and_18_retry_journal_directory_after_replace(self):
        def lose_rename(effect):
            trace = PublicationTrace(('replace', 'journal', 'after'))
            with trace.instrument(self.api), self.assertRaises(Cut):
                effect()

        def fail_journal_directory(path):
            if path == self.root:
                raise OSError('journal directory fsync')

        lose_rename(self.boot)
        self.assert_state('BLOCKED')
        digest = self.plan()['planSha256']
        with patch.object(self.api, 'sync', fail_journal_directory):
            for replay in (self.boot, lambda: self.apply(digest)):
                with self.assertRaisesRegex(OSError, 'journal directory fsync'):
                    replay()
        directory = self.archive / 'reconcile'
        self.assertFalse(directory.exists())
        self.boot()
        lose_rename(lambda: self.apply(digest))
        self.assert_state('QUIESCED')
        with patch.object(self.api, 'sync', fail_journal_directory), self.assertRaisesRegex(
                OSError, 'journal directory fsync'):
            self.apply(digest)
        self.assertFalse((directory / 'receipt.json').exists())
        self.apply(digest)
        with patch.object(self.api, 'sync', fail_journal_directory), self.assertRaisesRegex(
                OSError, 'journal directory fsync'):
            self.boot()
        self.boot()
        self.assertEqual(self.api.nft_writes, 1)

    def assert_retries_sync_file_and_parent(self, path, retry):
        fsync = os.fsync
        for failure in ('file', 'directory'):
            events = []

            def file_sync(fd):
                if os.path.samestat(os.fstat(fd), path.stat()):
                    events.append('file')
                    if failure == 'file':
                        raise OSError('file fsync')
                fsync(fd)

            def dir_sync(directory):
                if directory == path.parent and events == ['file']:
                    events.append('directory')
                    raise OSError('directory fsync')

            with self.subTest(path=path.name, failure=failure), patch.object(os, 'fsync', file_sync), \
                    patch.object(self.api, 'sync', dir_sync), self.assertRaisesRegex(OSError, failure):
                retry()
            self.assertEqual(events, ['file'] if failure == 'file' else ['file', 'directory'])

    def test_a3_18_retry_plan_and_receipt_before_fsync(self):
        self.boot()
        digest = self.plan()['planSha256']
        directory = self.archive / 'reconcile'
        for name in ('plan.json', 'receipt.json'):
            trace = PublicationTrace(('write', name, 'after'))
            with trace.instrument(self.api), self.assertRaises(Cut):
                self.apply(digest)
            before = self.snapshot()
            self.assertEqual(self.plan()['planSha256'], digest)
            self.assert_retries_sync_file_and_parent(directory / name, lambda: self.apply(digest))
            if name == 'plan.json':
                self.assert_state('BLOCKED')
                self.assertFalse(self.seal.exists())
            else:
                self.assert_state('QUIESCED')
                self.assert_retries_sync_file_and_parent(directory / name, self.boot)
            self.assertEqual(self.snapshot(), before)
        self.assertEqual(B.canonical(self.apply(digest)), (directory / 'receipt.json').read_bytes())
        self.boot()

    def test_a3_18_resume_complete_seal_before_fsync(self):
        self.boot()
        digest = self.plan()['planSha256']
        write_once = self.api.write_once

        def interrupt_seal(path, raw):
            if path != self.seal:
                return write_once(path, raw)
            with path.open('xb') as stream:
                stream.write(raw)
                stream.flush()
                raise Cut('before seal fsync')

        with patch.object(self.api, 'write_once', interrupt_seal), self.assertRaises(Cut):
            self.apply(digest)
        self.assert_state('BLOCKED')
        self.assertEqual(self.plan()['planSha256'], digest)
        cas = self.api.cas
        fsync = os.fsync
        events = []

        def sync_file(fd):
            fsync(fd)
            if os.path.samestat(os.fstat(fd), self.seal.stat()):
                events.append('file')

        def sync_directory(path):
            if path == self.seal.parent:
                events.append('directory')

        def transition(path, before, after):
            events.append('cas')
            cas(path, before, after)

        self.assert_retries_sync_file_and_parent(self.seal, lambda: self.apply(digest))
        self.assert_state('BLOCKED')
        with patch.object(os, 'fsync', sync_file), patch.object(self.api, 'sync', sync_directory), \
                patch.object(self.api, 'cas', transition):
            self.apply(digest)
        self.assertEqual(events, ['file', 'directory', 'cas'])
        self.assert_state('QUIESCED')

    def test_a3_18_interrupted_intent_without_seal_held(self):
        self.boot()
        digest = self.plan()['planSha256']
        self.api.cut = 'seal-intent.json'
        with self.assertRaises(Cut):
            self.apply(digest)
        with self.assertRaisesRegex(ValueError, g.SEAL_DRIFT):
            self.plan()
        self.assertTrue((self.archive / 'reconcile/plan.json').exists())
        self.assert_state('BLOCKED')

    def test_a3_19_foreign_or_lost_seal_held(self):
        self.boot()
        digest = self.plan()['planSha256']
        self.apply(digest)
        seal = B.document(self.seal.read_bytes())
        self.seal.write_bytes(B.canonical({**seal, 'bootId': OLD}))
        for effect in (self.plan, self.boot, lambda: self.apply(digest)):
            with self.assertRaises(ValueError):
                effect()
        self.seal.unlink()
        with self.assertRaises(ValueError):
            self.plan()

    def test_a3_19_missing_guard_and_missing_final_receipt(self):
        self.boot()
        digest = self.plan()['planSha256']
        self.apply(digest)
        (self.archive / 'reconcile/receipt.json').unlink()
        with self.assertRaises(FileNotFoundError):
            self.boot()
        self.apply(digest)
        (self.archive / 'guard.json').unlink()
        for effect in (self.boot, self.plan):
            with self.assertRaises(FileNotFoundError):
                effect()
        self.assert_state('QUIESCED')

    def test_a3_19_other_writer_cannot_convert_previous_boot(self):
        with self.api.lock(self.root / 'common.lock'), self.assertRaisesRegex(ValueError, g.BINDING):
            J.transition_locked(self.api, self.root / 'journal', self.previous, HEAD, self.live['owner'],
                                'BLOCKED')
        self.assertEqual(self.previous, (self.root / 'journal').read_bytes())

    def test_a3_19_current_boot_authority_edges_and_cas(self):
        self.boot()
        self.apply(self.plan()['planSha256'])
        raw = (self.root / 'journal').read_bytes()
        def move(before, to):
            with self.api.lock(self.root / 'common.lock'):
                J.transition_locked(self.api, self.root / 'journal', before, HEAD, self.live['owner'], to)
        move(raw, 'LEASE_READY')
        self.assertTrue(self.journal()['leaseAuthorized'])
        self.assertEqual(self.journal()['bootId'], NOW)
        with self.assertRaisesRegex(ValueError, 'FOREIGN_PUBLICATION'):
            move(raw, 'LEASE_UPDATING')
        with self.assertRaises(ValueError):
            self.boot()


class Format(unittest.TestCase):
    def test_a3_20_real_orders_same_lease_policy(self):
        footprints = []
        captures = []
        for version in ('1.0.9', '1.1.3'):
            rows = json.loads((FIXTURES / ('inet-v' + version + '.json')).read_bytes())['nftables']
            # Compare every captured object, including populated/multi-flag and
            # flagless sets, before selecting the compiler's closed grammar.
            captures.append(sorted(rows[1:], key=lambda row: next(iter(row))))
            kinds = [next(iter(row)) for row in rows]
            self.assertEqual(kinds.index('chain') < kinds.index('set'), version == '1.1.3')
            # Keep the lease subset of each real sample (the two additional
            # sets exercise non-lease flags); evaluate the same empty policy.
            rows = [r for r in rows if 'set' not in r or r['set']['name'] == 'provider_0']
            next(r['set'] for r in rows if 'set' in r).pop('elem')
            pair = {'inet': {'nftables': rows}, 'bridge': {'nftables': copy.deepcopy(rows)}}
            for row in pair['bridge']['nftables'][1:]:
                next(iter(row.values()))['family'] = 'bridge'
            profile = {'version': version, 'jsonSchemaVersion': 1}
            footprints.append(g.policy_footprint(pair, profile))
            for doc in pair.values():
                # Even a rule before its chain can be resolved after parsing.
                doc['nftables'].append(doc['nftables'].pop(next(i for i, r in enumerate(doc['nftables'])
                                                                if 'chain' in r)))
            self.assertEqual(footprints[-1], g.policy_footprint(pair, profile))
        self.assertEqual(*captures)
        self.assertEqual(*footprints)

    def test_a3_21_truncated_seconds_renewal_margin(self):
        for margin in (4, 5, 6, True, float('inf'), float('nan')):
            with self.assertRaisesRegex(ValueError, g.TTL):
                g.verify_renewal_margin(margin, 5)
        g.verify_renewal_margin(7, 5)
        g.verify_renewal_margin(2, 0.5)
