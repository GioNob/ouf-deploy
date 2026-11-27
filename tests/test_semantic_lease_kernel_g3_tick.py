"""Portable PET for the G3 runtime consumers with real files and journal edges."""
import copy
from contextlib import contextmanager, redirect_stdout
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.semantic_lease_kernel_migration import g3_contract as g, g3_journal as J, g3_reconcile as R
from tools.semantic_provider_operation import lease_supervisor_g3 as T
from tools.semantic_provider_r3 import lease_kernel_g3 as K, operate as O
from test_semantic_lease_kernel_g3_boot import B, Cut, Fake, FIXTURES, HEAD, NOW, OLD, ROOT, PublicationTrace, runner, stage
from test_semantic_lease_kernel_v2 import kernel, observations, refresh


def context(root, live):
    coordinator = dict(ownerConfiguration={'path': str(root / 'owner'), 'sha256': live['owner']},
                       journalPath=str(root / 'journal'), commonLockPath=str(root / 'common.lock'),
                       bootPointer=str(root / 'pointer'))
    head = dict(sha256=live['head'], decision='OPERATE', authorization={'lease': {
        'ownerConfigurationSha256': live['owner'], 'projection': g.PROJECTION, 'footprint': live['footprint']}})
    return coordinator, head


@contextmanager
def exclusive(api, path):
    with open(path, 'r+b') as handle:
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with Fake.lock(api, path):
            yield


class Scenario:
    def __init__(self, root, version, receipt_cut=False):
        self.root = root
        rows = json.loads((FIXTURES / f'inet-v{version}.json').read_bytes())['nftables']
        rows = [r for r in rows if 'set' not in r or r['set']['name'] == 'provider_0']
        pair = {family: {'nftables': copy.deepcopy(rows)} for family in ('inet', 'bridge')}
        self.address = next(r['set'] for r in rows if 'set' in r)['elem'][0]['elem']['val']
        for family, doc in pair.items():
            for row in doc['nftables'][1:]:
                next(iter(row.values()))['family'] = family
                if 'set' in row:
                    del row['set']['elem']
        self.api = api = Fake(pair)
        cfg = {**kernel(2), 'tableName': 'sample'}
        cfg['providerFlows'][0].update(addresses=[self.address], allowedPrivateAddresses=[self.address])
        self.receipt, live = stage(root, api, cfg, {'path': '/fixture/nft', 'sha256': HEAD},
                                   pair, runtime=True)
        self.coordinator, self.head = context(root, live)
        self.owner = api.document(api.private(root / 'owner'))
        self.seal = root / 'seals' / (NOW + '.json')
        self.denial = root / 'receipts' / (NOW + '.tick-denied.json')
        api.current = copy.deepcopy(pair)
        with patch.object(runner, '_journal_module', return_value=J), patch.object(J, 'cohort_empty'):
            with api.lock(root / 'common.lock'):
                runner.run(self.receipt, api)
        observe = lambda state: {**live, 'bootId': NOW}
        planned = R.plan(root / 'pointer', observe, api)
        if receipt_cut:
            trace = PublicationTrace(('write', 'receipt.json', 'after'))
            with trace.instrument(api), unittest.TestCase().assertRaises(Cut):
                R.apply(root / 'pointer', planned['planSha256'], observe, api)
        else:
            R.apply(root / 'pointer', planned['planSha256'], observe, api)
        self.predecessor = None
        def tables(nft, name):
            assert api.held == ['common.lock']
            if name == self.owner['predecessorTableName']:
                return self.predecessor
            assert name == cfg['tableName']
            return Fake.tables(api, nft, name)
        api.tables = tables
        self.batch_count = 0
        self.events = []
        self.cut = None
        def point(effect, phase):
            if phase in ('before', 'after'):
                self.events.append((effect, phase))
            if self.cut == (effect, phase):
                self.cut = None
                raise Cut()
        def cas(path, before, after):
            effect = 'admission' if Path(path) == root / 'admission' else api.document(after)['state']
            point(effect, 'before')
            fsync, replace = os.fsync, os.replace
            def sync_temp(fd):
                point(effect, 'written')
                return fsync(fd)
            def rename(src, dst):
                replace(src, dst)
                point(effect, 'renamed')
            with patch.object(os, 'fsync', sync_temp), patch.object(os, 'replace', rename):
                Fake.cas(api, path, before, after)
            point(effect, 'after')
        api.cas = cas
        def write(path, raw):
            if path != self.denial:
                return Fake.write_once(api, path, raw)
            point('denial', 'before')
            fsync, sync = os.fsync, api.sync
            def sync_file(fd):
                point('denial', 'written')
                fsync(fd)
            def sync_dir(directory):
                point('denial', 'before-dir-sync')
                sync(directory)
            with patch.object(os, 'fsync', sync_file), patch.object(api, 'sync', sync_dir):
                Fake.write_once(api, path, raw)
            point('denial', 'after')
        api.write_once = write
        def command(nft, argv, raw):
            assert api.held == ['common.lock'] and argv == ['-f', '-']
            assert set(raw.decode('ascii').splitlines()) == {
                line for f in ('inet', 'bridge') for line in (
                    f'flush set {f} sample provider_0',
                    f'add element {f} sample provider_0 {{ {self.address} timeout 28s }}')}
            point('batch', 'before')
            self.batch_count += 1
            self.populate(28)
            point('batch', 'after')
        api.command = command
        self.generation = 1

    @contextmanager
    def guarded_batch(self):
        expected = self.generation
        def submit(table, transaction):
            self.api.need(expected == self.generation, T.nft_batch_g3.CONFLICT)
            self.api.command(self.owner['nftPath'], ['-f', '-'], transaction.encode('ascii'))
        yield submit

    def journal(self):
        return self.api.document(self.api.private(self.root / 'journal'))

    def populate(self, ttl):
        for d in self.api.current.values():
            row = next(r['set'] for r in d['nftables'] if 'set' in r)
            row['elem'] = [{'elem': {'val': self.address, 'expires': ttl, 'timeout': ttl}}]

    def ready(self):
        with K.locked(self.coordinator, self.api) as state:
            state.verify(state.local_reference(), state.read_pair())
            admission = state.admission({'provider_0': {self.address: 120}})
            Fake.write_once(self.api, self.root / 'admission', B.canonical(admission))
            self.populate(18)
            state.transition('LEASE_READY')
        self.events.clear()

    def tick(self, clock=lambda: 100.0):
        def resolve(owner):
            assert self.api.held == ['common.lock']
            return observations(owner['kernel'])
        with patch.object(T.nft_batch_g3, 'guarded_batch', self.guarded_batch):
            return T.tick(self.coordinator, lambda: self.head, resolve, refresh.compile_refresh,
                          api=self.api, clock=clock)

    def operate(self):
        observe = K.observe
        with patch.object(K, 'observe', side_effect=lambda *args, **kw: observe(
                *args, api=self.api, clock=lambda: 100, **kw)):
            return O.lease_kernel_state(self.owner, self.journal(), None, None,
                                        coordinator=self.coordinator, head=self.head)


class Tick(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(J, 'current_boot_id', return_value=NOW))
        self.enterContext(patch.object(J, 'private_directory', lambda api, p: api.need(p.is_dir(), g.BINDING)))

    def scenario(self, version='1.1.3', **options):
        return Scenario(Path(self.enterContext(tempfile.TemporaryDirectory(dir=ROOT))), version, **options)

    def test_a3_23_renew_and_operate_both_formats(self):
        for version in ('1.0.9', '1.1.3'):
            with self.subTest(version=version):
                s = self.scenario(version)
                gate = s.operate()
                self.assertEqual(gate['generation'], 3)
                s.ready()
                self.assertEqual(s.tick(), {'state': 'LEASE_READY', 'nextTickMonotonic': 105})
                self.assertEqual(s.batch_count, 1)
                self.assertEqual(s.operate(), gate)
                self.assertEqual(s.journal()['bootId'], NOW)
                self.assertEqual(s.events[::2], [(e, 'before') for e in
                                 ('LEASE_UPDATING', 'batch', 'admission', 'LEASE_READY')])

    def test_a3_24_invalid_members_ttl_binding_or_instance_blocks_before_batch(self):
        for failure, code in [('members', g.MEMBERS), ('ttl', g.TTL), ('boot', g.BINDING),
                              ('handles', g.SEAL_DRIFT), ('policy', g.BINDING)]:
            with self.subTest(failure=failure):
                s = self.scenario()
                s.ready()
                rows = s.api.current['bridge']['nftables']
                member = next(r['set']['elem'][0]['elem'] for r in rows if 'set' in r)
                if failure == 'members':
                    member['val'] = '192.0.2.13'
                elif failure == 'ttl':
                    member['expires'] = 90
                elif failure == 'boot':
                    s.seal.write_bytes(B.canonical({**B.document(s.seal.read_bytes()), 'bootId': OLD}))
                elif failure == 'handles':
                    rows[1]['table']['handle'] += 1
                else:
                    s.head['authorization']['lease']['footprint'] = '0' * 64
                with self.assertRaisesRegex(ValueError, code):
                    s.tick()
                self.assertEqual(s.batch_count, 0)
                self.assertEqual((s.journal()['state'], s.journal()['leaseAuthorized'],
                                  s.journal()['startAuthorized']), ('BLOCKED', False, False))
                self.assertEqual(B.document(s.denial.read_bytes())['reason'], code)

    def test_a3_25_start_denies_evidence_drift_and_partial_pair(self):
        for failure in ('absent', 'boot', 'completion', 'predecessor', 'bridge', 'journalBoot',
                        'startFlag', 'leaseFlag', 'populated', 'blocked', 'head'):
            with self.subTest(failure=failure):
                s = self.scenario()
                if failure == 'absent':
                    s.seal.unlink()
                elif failure == 'boot':
                    s.seal.write_bytes(B.canonical({**B.document(s.seal.read_bytes()), 'bootId': OLD}))
                elif failure == 'completion':
                    (s.root / 'receipts' / NOW / 'reconcile' / 'receipt.json').unlink()
                elif failure == 'predecessor':
                    s.predecessor = s.api.template
                elif failure == 'bridge':
                    del s.api.current['bridge']
                elif failure == 'populated':
                    s.populate(18)
                elif failure == 'head':
                    s.head['decision'] = 'STOP'
                else:
                    change = {'journalBoot': {'bootId': OLD}, 'startFlag': {'startAuthorized': True},
                              'leaseFlag': {'leaseAuthorized': True}, 'blocked': {'state': 'BLOCKED'}}[failure]
                    (s.root / 'journal').write_bytes(B.canonical({**s.journal(), **change}))
                with self.assertRaises(O.A.OperationDenied):
                    s.operate()

    def test_a3_26_cut_each_renewal_publication(self):
        for effect in ('LEASE_UPDATING', 'batch', 'admission', 'LEASE_READY'):
            for side in (('before', 'after') if effect == 'batch' else ('before', 'written', 'renamed', 'after')):
                with self.subTest(effect=effect, side=side):
                    s = self.scenario()
                    s.ready()
                    s.cut = (effect, side)
                    with self.assertRaises(Cut):
                        s.tick()
                    if s.journal()['state'] == 'LEASE_UPDATING':
                        count = s.batch_count
                        with self.assertRaisesRegex(ValueError, 'G3_INTERRUPTED_RENEWAL'):
                            s.tick()
                        self.assertEqual(s.journal()['state'], 'BLOCKED')
                        self.assertEqual(s.batch_count, count)
                        self.assertTrue((s.root / 'admission').is_file())
                    else:
                        self.assertEqual(s.tick()['state'], 'LEASE_READY')
                        self.assertEqual(s.journal()['state'], 'LEASE_READY')

    def test_a3_27_cut_denial_receipt_and_blocked_transition(self):
        for effect in ('denial', 'BLOCKED'):
            for side in ('before', 'written', 'before-dir-sync' if effect == 'denial' else 'renamed', 'after'):
                with self.subTest(effect=effect, side=side):
                    s = self.scenario()
                    s.ready()
                    s.api.current['bridge']['nftables'][1]['table']['handle'] += 1
                    s.cut = (effect, side)
                    with self.assertRaises(Cut):
                        s.tick()
                    with self.assertRaises(ValueError):
                        s.tick()
                    self.assertEqual(s.batch_count, 0)
                    self.assertEqual(s.journal()['state'], 'BLOCKED')
                    self.assertTrue(s.seal.is_file())
                    self.assertTrue((s.root / 'admission').is_file())

    def test_a3_28_post_batch_drift_preserves_admission(self):
        s = self.scenario()
        s.ready()
        old = (s.root / 'admission').read_bytes()
        apply = s.api.command
        def change(*args):
            apply(*args)
            s.api.current['inet']['nftables'][1]['table']['handle'] += 1
        s.api.command = change
        with self.assertRaisesRegex(ValueError, g.SEAL_DRIFT):
            s.tick()
        self.assertEqual((s.root / 'admission').read_bytes(), old)
        self.assertEqual(s.journal()['state'], 'BLOCKED')

    @contextmanager
    def fail_confirmation(self, s, path, failure):
        fsync, sync = os.fsync, s.api.sync
        events = []
        def file_sync(fd):
            if os.path.samestat(os.fstat(fd), path.stat()):
                self.assertEqual(s.api.held, ['common.lock'])
                events.append('file')
                if failure == 'file':
                    raise OSError('file fsync')
            fsync(fd)
        def dir_sync(directory):
            if directory == path.parent and events == ['file']:
                events.append('directory')
                if failure == 'directory':
                    raise OSError('directory fsync')
            sync(directory)
        with patch.object(os, 'fsync', file_sync), patch.object(s.api, 'sync', dir_sync):
            yield
        self.assertEqual(events, ['file'] if failure == 'file' else ['file', 'directory'])

    def test_a3_26_runtime_retries_file_and_directory_before_confirming(self):
        s = self.scenario(receipt_cut=True)
        def check_gate(path):
            before = path.read_bytes()
            for failure in ('file', 'directory'):
                with self.fail_confirmation(s, path, failure), self.assertRaisesRegex(
                        O.A.OperationDenied, 'G3_EVIDENCE'):
                    s.operate()
                self.assertEqual(path.read_bytes(), before)
            with self.fail_confirmation(s, path, None):
                self.assertEqual(s.operate()['bootId'], NOW)
        check_gate(s.root / 'receipts' / NOW / 'reconcile' / 'receipt.json')
        s.ready()
        s.cut = ('LEASE_READY', 'renamed')
        with self.assertRaises(Cut):
            s.tick()
        check_gate(s.root / 'journal')
        check_gate(s.root / 'admission')

    def test_a3_27_failed_sync_on_denial_replay_keeps_evidence_and_revokes(self):
        for failure in ('file', 'directory'):
            with self.subTest(failure=failure):
                s = self.scenario()
                s.ready()
                s.populate(99)
                s.cut = ('denial', 'written')
                with self.assertRaises(Cut):
                    s.tick()
                raw = s.denial.read_bytes()
                with self.fail_confirmation(s, s.denial, failure), self.assertRaisesRegex(
                        ValueError, 'G3_DENIAL_EVIDENCE'):
                    s.tick()
                self.assertEqual(s.denial.read_bytes(), raw)
                self.assertEqual(s.journal()['state'], 'BLOCKED')
                self.assertEqual(s.batch_count, 0)

    def test_a3_26_retry_after_rename_with_directory_still_failing(self):
        for effect in ('LEASE_UPDATING', 'admission', 'LEASE_READY', 'BLOCKED'):
            with self.subTest(effect=effect):
                s = self.scenario()
                s.ready()
                if effect == 'BLOCKED':
                    s.populate(99)
                s.cut = (effect, 'renamed')
                with self.assertRaises(Cut):
                    s.tick()
                destination = s.root / ('admission' if effect == 'admission' else 'journal')
                visible = destination.read_bytes()
                batches = s.batch_count
                with self.fail_confirmation(s, s.root / 'journal', 'directory'), self.assertRaises(OSError):
                    s.tick()
                self.assertEqual(s.batch_count, batches)
                self.assertEqual(destination.read_bytes(), visible)
                if effect == 'LEASE_READY':
                    self.assertEqual(s.tick()['state'], 'LEASE_READY')
                else:
                    with self.assertRaises(ValueError):
                        s.tick()
                    self.assertEqual(s.journal()['state'], 'BLOCKED')
                    self.assertEqual(s.batch_count, batches)

    def test_a3_29_replacement_between_verify_and_submit(self):
        s = self.scenario()
        s.ready()
        guard = s.guarded_batch
        @contextmanager
        def replacing():
            with guard() as submit:
                def race(table, transaction):
                    s.generation += 1
                    s.api.current = copy.deepcopy(s.api.template)
                    s.api.current['bridge']['nftables'][1]['table']['handle'] += 1
                    submit(table, transaction)
                yield race
        s.guarded_batch = replacing
        with self.assertRaisesRegex(ValueError, g.SEAL_DRIFT):
            s.tick()
        self.assertEqual(s.batch_count, 0)
        B.empty(s.api.current)
        self.assertEqual(s.journal()['state'], 'BLOCKED')

    def test_a3_29_generation_bound_wire_batch_and_conflict(self):
        batch = T.nft_batch_g3
        generation_id = 0x12345678
        def reply(kind, seq, body):
            raw = struct.pack('=IHHII', 16 + len(body), kind, 0, seq, 0) + body
            return raw, [], 0, (0, 0)
        gen = reply(0x0a0f, 1, bytes(4) + struct.pack('=HH', 8, 1) + struct.pack('!I', generation_id))
        lines = ('flush set inet sample provider_0\nflush set bridge sample provider_1\n'
                 'add element inet sample provider_0 { 192.0.2.12 timeout 28s }\n'
                 'add element bridge sample provider_1 { 2001:db8::1 timeout 18s }\n')
        for conflict in (False, True):
            sock = MagicMock()
            replies = ([reply(2, 2, struct.pack('=i', -85))] if conflict else
                       [reply(2, seq, bytes(4)) for seq in range(3, 7)])
            sock.recvmsg.side_effect = [gen, *replies]
            with patch.object(batch.socket, 'MSG_TRUNC', 32, create=True), \
                    patch.object(batch.errno, 'ERESTART', 85, create=True):
                observed = batch.generation(sock)
                self.assertEqual(observed, generation_id)
                if conflict:
                    with self.assertRaisesRegex(ValueError, batch.CONFLICT):
                        batch.submit(sock, observed, 'sample', lines)
                else:
                    batch.submit(sock, observed, 'sample', lines)
            self.assertEqual(sock.sendto.call_count, 2)
            raw, peer = sock.sendto.call_args.args
            self.assertEqual(peer, (0, 0))
            messages = []
            while raw:
                length, kind, flags, sequence, _ = struct.unpack_from('=IHHII', raw)
                messages.append((kind, sequence, raw[16:length]))
                raw = raw[length:]
            self.assertEqual([r[:2] for r in messages],
                             [(16, 2), (0xa0e, 3), (0xa0e, 4), (0xa0c, 5), (0xa0c, 6), (17, 7)])
            self.assertEqual(messages[0][2], b'\0\0\0\x0a' + struct.pack('=HH', 8, 1)
                             + struct.pack('!I', generation_id))
            self.assertEqual([r[2][0] for r in messages[1:-1]], [1, 7, 1, 7])
            self.assertIn(bytes.fromhex('c000020c'), messages[3][2])
            self.assertIn(bytes.fromhex('20010db8000000000000000000000001'), messages[4][2])
            self.assertTrue(messages[3][2].endswith(struct.pack('!Q', 28000)))
            self.assertTrue(messages[4][2].endswith(struct.pack('!Q', 18000)))

    @contextmanager
    def start_plan(self):
        from test_semantic_provider_r3_v12 import StartGate
        s = self.scenario()
        with StartGate().observation_fixture() as (args, _, journal, _, runtime):
            args.nft, args.nft_sha256 = s.owner['nftPath'], s.owner['nftSha256']
            args.output_directory = str(s.root / 'output')
            journal.clear()
            journal.update(s.journal())
            head = runtime.authorization_head()
            head.update(sha256=s.head['sha256'])
            head['authorization']['lease'] = s.head['authorization']['lease']
            sup = B.document(runtime.bound_bytes({}))
            args.install_root = s.root.as_posix()
            cfg, _ = runtime.load_configuration(None)
            sup['registryRoot'] = cfg['registryRoot'] = (s.root / 'registry').as_posix()
            chain = s.root / 'authorization'
            chain.mkdir()
            sup['authorizationRoot'] = cfg['operation']['authorizationRoot'] = chain.as_posix()
            Fake.write_once(s.api, chain / '12.json', B.canonical(head['authorization']))
            Fake.write_once(s.api, chain / '12.signature.json', B.canonical({'signature': 'fixture'}))
            sup['coordinator'] = s.coordinator
            runtime.bound_bytes = lambda ref: B.canonical(
                s.owner if ref == s.coordinator['ownerConfiguration'] else sup)
            switch = O.I.native_switch()
            custody = switch.custody
            switch.custody = lambda p, mode: (((s.root / 'journal').read_bytes(), ()) if str(p) == s.coordinator['journalPath']
                                               else custody(p, mode))
            switch.sync = s.api.sync
            s.runtime = runtime
            observe = K.observe
            gate = K.submission_gate
            def nft(argv, *, stdout, **kwargs):
                self.assertEqual(s.api.held, ['common.lock'])
                name = s.owner['kernel']['tableName']
                if argv[1:] == ['-j', 'list', 'tables']:
                    doc = {'nftables': [{'table': {'name': name, 'family': f}} for f in ('inet', 'bridge')]}
                else:
                    self.assertEqual(argv[1:], ['-j', 'list', 'table', argv[4], name])
                    doc = s.api.current[argv[4]]
                stdout.write(B.canonical(doc))
                return SimpleNamespace(returncode=0)
            with patch.object(K, 'observe', side_effect=lambda *args, **kw: observe(*args, api=s.api, **kw)), \
                    patch.object(s.api, 'executable', side_effect=lambda path, digest: path, create=True), \
                    patch.object(K, 'subprocess', SimpleNamespace(run=nft, DEVNULL=K.subprocess.DEVNULL)), \
                    patch.object(K, 'submission_gate', side_effect=lambda *a: gate(*a, api=s.api)), \
                    patch.object(O.I, 'write_once', side_effect=lambda p, raw, report: Fake.write_once(s.api, p, raw)):
                plan = O.proposal(args, O.observe(args))
                args.plan_sha256 = plan['planSha256']
                yield s, args, plan

    def test_a3_30_operate_plan_apply_rechecks_seal_before_docker(self):
        from test_semantic_provider_r3_operate import successful
        with self.start_plan() as (s, args, plan), patch.object(O.VR, 'apply', side_effect=lambda *a: s.seal.unlink()):
            before = plan['observation']
            self.assertEqual(before['leaseKernel']['generation'], 3)
            after = successful('start', before)
            after.update(configurationSha256=before['configurationSha256'], authorization=before['authorization'],
                         leaseKernel=before['leaseKernel'].copy())
            after['supervisor']['authorizationSequence'] = before['authorization']['sequence']
            for role in O.ROLES:
                after['candidates'][role]['cid'] = before['candidates'][role]['cid']
            self.assertTrue(O.reached(args, before, after))
            after['leaseKernel']['bootId'] = OLD
            self.assertFalse(O.reached(args, before, after))
            report = dict(O.COUNTERS)
            with self.assertRaisesRegex(O.A.OperationDenied, g.SEAL_DRIFT):
                O.apply(args, plan, report)
            self.assertEqual(report['dockerStartRequests'], 0)
            self.assertTrue((Path(args.output_directory) / 'operate-claim.json').is_file())

    def test_a3_30_revocation_before_admission_and_during_both_sends(self):
        for revoke_first in (True, False):
            with self.subTest(revoke_first=revoke_first), self.start_plan() as (s, args, plan):
                path = s.root / 'common.lock'
                def revoke():
                    with exclusive(s.api, path):
                        J.transition_locked(s.api, s.root / 'journal', B.canonical(s.journal()),
                                            HEAD, s.head['authorization']['lease']['ownerConfigurationSha256'], 'BLOCKED')
                sent = []
                def sendall(raw):
                    with self.assertRaises(OSError):
                        revoke()
                    sent.append(raw.split(b'\r\n', 1)[0])
                released = threading.Event()
                gate = K.submission_gate
                @contextmanager
                def admission(*context):
                    with gate(*context) as verify:
                        yield verify
                    released.set()
                def response():
                    self.assertTrue(released.wait(5))
                    self.assertFalse(s.api.held)
                    reply = MagicMock()
                    reply.__enter__.return_value.status = 204
                    return reply
                report = dict(O.COUNTERS)
                with patch.object(s.api, 'lock', lambda p: exclusive(s.api, p)), patch.object(O, 'poll'), \
                        patch.object(K, 'submission_gate', admission), \
                        patch.object(O.VR, 'apply', side_effect=lambda *a: revoke() if revoke_first else None), \
                        patch.object(K.socket, 'AF_UNIX', 1, create=True), \
                        patch.object(K, 'EngineSocket') as connect, \
                        patch.object(K.http.client.HTTPConnection, 'getresponse', side_effect=response):
                    connect.return_value.sendall.side_effect = sendall
                    if revoke_first:
                        with self.assertRaisesRegex(O.A.OperationDenied, 'G3_JOURNAL_DENIED'):
                            O.apply(args, plan, report)
                        connect.assert_not_called()
                        self.assertEqual(report['dockerStartRequests'], 0)
                    else:
                        O.apply(args, plan, report)
                        cids = [plan['observation']['candidates'][r]['cid'] for r in O.ROLES]
                        self.assertEqual(sent, [f'POST /v1.44/containers/{cid}/start HTTP/1.1'.encode()
                                                for cid in cids])
                        revoke()
                    self.assertEqual(s.journal()['state'], 'BLOCKED')

    def test_a3_30_selection_change_with_same_seal_denies_both_posts(self):
        with self.start_plan() as (s, args, plan):
            def reselect(*_):
                with s.api.lock(s.root / 'common.lock'):
                    path = s.root / 'pointer'
                    before = s.api.private(path)
                    pointer = B.document(before)
                    successor = s.root / 'successor-receipt'
                    Fake.write_once(s.api, successor, s.api.private(pointer['receiptFile']))
                    Fake.cas(s.api, path, before, B.canonical({**pointer, 'receiptFile': str(successor)}))
            report = dict(O.COUNTERS)
            with patch.object(O.VR, 'apply', side_effect=reselect), patch.object(K, 'connect_request') as send, \
                    self.assertRaisesRegex(O.A.OperationDenied, 'G3_BINDING'):
                O.apply(args, plan, report)
            send.assert_not_called()
            self.assertEqual(report['dockerStartRequests'], 0)
            self.assertEqual(s.journal()['state'], 'QUIESCED')

    def test_a3_31_denial_partial_receipt_and_lost_journal_cas(self):
        s = self.scenario()
        s.ready()
        s.populate(99)
        def partial(path, raw):
            if path != s.denial:
                return Fake.write_once(s.api, path, raw)
            path.write_bytes(raw[:12])
            raise Cut()
        s.api.write_once = partial
        with self.assertRaises(Cut):
            s.tick()
        partial_raw = s.denial.read_bytes()
        s.populate(18)
        with self.assertRaisesRegex(ValueError, 'G3_PRIOR_DENIAL'):
            s.tick()
        self.assertEqual(s.denial.read_bytes(), partial_raw)
        self.assertEqual(s.journal()['state'], 'BLOCKED')
        self.assertEqual(s.batch_count, 0)

        s = self.scenario()
        s.ready()
        foreign = B.canonical({**s.journal(), 'state': 'QUIESCING', 'leaseAuthorized': False})
        def conflict(path, before, after):
            Path(path).write_bytes(foreign)
            Fake.cas(s.api, path, before, after)
        s.api.cas = conflict
        with self.assertRaisesRegex(ValueError, 'FOREIGN_PUBLICATION_PRESERVED'):
            s.tick()
        self.assertEqual((s.root / 'journal').read_bytes(), foreign)
        self.assertFalse(s.denial.exists())
        self.assertEqual(s.batch_count, 0)

    def test_a3_32_effect_deadline_and_renewal_margin(self):
        for target, batches in [('LEASE_UPDATING', 0), ('admission', 1), ('LEASE_READY', 1)]:
            with self.subTest(target=target):
                s = self.scenario()
                s.ready()
                clock = [100.0]
                cas = s.api.cas
                def delayed(path, before, after):
                    cas(path, before, after)
                    value = B.document(after)
                    if value.get('state', 'admission') == target:
                        clock[0] += 6
                s.api.cas = delayed
                with self.assertRaisesRegex(ValueError, g.TTL):
                    s.tick(lambda: clock[0])
                self.assertEqual(s.batch_count, batches)
                self.assertEqual(s.journal()['state'], 'BLOCKED')

    def test_a3_33_g2_plan_followed_by_g3_has_no_post(self):
        from test_semantic_provider_r3_v12 import StartGate
        with StartGate().observation_fixture() as (legacy, *_):
            previous = O.observe(legacy)
        with self.start_plan() as (s, args, _):
            plan = O.proposal(args, previous)
            args.plan_sha256 = plan['planSha256']
            final = O.observe(args, for_submission=True)
            self.assertEqual([previous['leaseKernel']['generation'], final[0]['leaseKernel']['generation']], [2, 3])
            report = dict(O.COUNTERS)
            with patch.object(O, 'observe', side_effect=[previous, final]), patch.object(O.VR, 'apply'), \
                    patch.object(K, 'connect_request') as connect, patch.object(O, 'docker') as cli, \
                    self.assertRaisesRegex(O.A.OperationDenied, 'GENERATION_DRIFT'):
                O.apply(args, plan, report)
            connect.assert_not_called()
            cli.assert_not_called()
            self.assertEqual(report['dockerStartRequests'], 0)

    def test_a3_33_g2_supervisor_checks_live_generation_at_send(self):
        from test_semantic_provider_r3_v12 import StartGate
        s = self.scenario()
        with StartGate().observation_fixture() as (args, owner, row, _, runtime):
            _, (coordinator, approved, _, _, _) = O.observe(args, for_submission=True)
            authenticate = lambda api: runtime.authorization_head()
            coordinator = {**coordinator, 'bootPointer': s.coordinator['bootPointer'],
                           'commonLockPath': s.coordinator['commonLockPath']}
            owner = {**owner, 'commonLockFile': coordinator['commonLockPath'], 'journalFile': str(s.root / 'g2-journal')}
            Fake.write_once(s.api, Path(owner['journalFile']), B.canonical(row))
            path = Path(coordinator['bootPointer'])
            successor = path.read_bytes()
            receipt = {**s.receipt, 'generation': 2, 'configurationHash': coordinator['ownerConfiguration']['sha256'],
                       'predecessorTableName': owner['kernel']['tableName'][:-3]}
            old = s.root / 'g2-receipt'
            Fake.write_once(s.api, old, B.canonical(receipt))
            pointer = B.canonical({**B.document(successor), 'receiptFile': str(old), 'receiptHash': B.digest(receipt)})
            Fake.cas(s.api, path, successor, pointer)
            name = owner['kernel']['tableName']
            tables = {f: O.decode(O.command(args.nft, args.nft_sha256, ['-j', 'list', 'table', f, name], 1))
                      for f in ('inet', 'bridge')}
            with patch.object(s.api, 'tables', side_effect=lambda _, n: tables if n == name else None):
                with K.submission_gate(coordinator, approved, owner, row, authenticate, api=s.api) as check:
                    check()
                with s.api.lock(coordinator['commonLockPath']):
                    Fake.cas(s.api, path, pointer, successor)
                with K.submission_gate(coordinator, approved, owner, row, authenticate, api=s.api) as check, \
                        self.assertRaisesRegex(ValueError, 'GENERATION_DRIFT'):
                    check()

    def held_start(self, args):
        args.apply, args.plan = True, False
        with patch.object(O, 'arguments', return_value=args), patch.object(O.sys, 'platform', 'linux'), \
                patch.object(O.os, 'umask'), patch.object(O.os, 'geteuid', return_value=0, create=True), \
                patch.object(O.os, 'getegid', return_value=0, create=True), redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(O.main([]), 1)
        return json.loads(stdout.getvalue())

    def test_a3_34_head_and_seal_rechecked_before_each_post(self):
        from test_semantic_provider_operation_issuance import issue
        for effect in ('head', 'handles'):
            for sent_before_change in (0, 1):
                with self.subTest(effect=effect, sent=sent_before_change), self.start_plan() as (s, args, plan):
                    client = MagicMock()
                    def change():
                        if effect == 'head':
                            previous = s.runtime.authorization_head()
                            s.runtime.authorization_head = lambda *a: {**previous, 'sha256': 'e' * 64}
                        else:
                            s.api.current['bridge']['nftables'][1]['table']['handle'] += 1
                    def connect(*_):
                        if not sent_before_change:
                            change()
                        return client, '/fixture'
                    def send(*_args, **_kwargs):
                        # A second open of the writer's lock must contend even inside send().
                        with self.assertRaises(OSError), issue.publication_lock(
                                s.root, s.head, B.canonical(s.owner), s.coordinator['ownerConfiguration']):
                            self.fail('issuer entered during POST')
                        with self.assertRaises(OSError):
                            R.apply(s.coordinator['bootPointer'], 'unused', api=s.api)
                        change()
                    client.request.side_effect = send
                    client.getresponse.return_value.__enter__.return_value.status = 204 if effect == 'head' else 503
                    inspect = O.docker
                    first, second = (plan['observation']['candidates'][r]['cid'] for r in O.ROLES)
                    def docker(args, verb, cid, **kwargs):
                        raw = inspect(args, verb, cid, **kwargs)
                        if cid == first and client.getresponse.called:
                            row, = json.loads(raw)
                            row['State'].update(Status='running', Running=True, Pid=231)
                            return B.canonical([row])
                        return raw
                    with patch.object(s.api, 'lock', lambda p: exclusive(s.api, p)), \
                            patch.object(issue.boot, 'lock', side_effect=s.api.lock), \
                            patch.object(K, 'connect_request', side_effect=connect), patch.object(O.VR, 'apply'), \
                            patch.object(O, 'docker', docker):
                        emitted = self.held_start(args)
                    report = json.loads((Path(args.output_directory) / 'result.json').read_bytes())
                    self.assertEqual(report, emitted)
                    self.assertEqual(report['status'], 'HELD')
                    reason = 'R3_AUTHORIZATION_CHANGED_DURING_OBSERVATION' if effect == 'head' else g.SEAL_DRIFT
                    self.assertEqual(client.request.call_count, sent_before_change)
                    self.assertEqual(report['dockerStartRequests'], sent_before_change)
                    self.assertEqual(client.getresponse.call_count, sent_before_change)
                    if sent_before_change:
                        self.assertEqual(report['reason'], 'R3_PARTIAL_START_DENIED')
                        self.assertEqual(report['deniedRequest'], {'role': 'southbound', 'reason': reason})
                        errors = [] if effect == 'head' else [{'role': 'adapter', 'reason': 'R3_DOCKER_REQUEST_FAILED'}]
                        self.assertEqual(report['requestErrors'], errors)
                        partial = report['partialObservation']
                        self.assertEqual([(r['cid'], r['postAttempted'], r['docker']['Status'], r['docker']['Pid'])
                                          for r in (partial['adapter'], partial['southbound'])],
                                         [(first, True, 'running', 231), (second, False, 'exited', 0)])
                    else:
                        self.assertEqual(report['reason'], reason)

    def test_a3_34_partial_result_interrupted_before_file_or_directory_sync(self):
        write_once = O.I.write_once
        for failed_sync in ('file', 'directory'):
            with self.subTest(failed_sync=failed_sync), self.start_plan() as (s, args, _):
                result = Path(args.output_directory) / 'result.json'
                client = MagicMock()
                client.getresponse.return_value.__enter__.return_value.status = 204
                def send(*args, **kwargs):
                    s.api.current['bridge']['nftables'][1]['table']['handle'] += 1
                client.request.side_effect = send
                switch = O.I.native_switch()
                fsync, sync = os.fsync, switch.sync
                attempts = []
                def file_sync(fd):
                    if result.exists() and os.path.samestat(result.stat(), os.fstat(fd)):
                        attempts.append('file')
                        if failed_sync == 'file':
                            raise OSError('interrupted file sync')
                    fsync(fd)
                def dir_sync(path):
                    if path == result.parent and result.exists():
                        attempts.append('directory')
                        if failed_sync == 'directory':
                            raise OSError('interrupted directory sync')
                    sync(path)
                with patch.object(O.I, 'write_once', write_once), patch.object(switch, 'sync', dir_sync), \
                        patch.object(os, 'fsync', file_sync), patch.object(os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True), \
                        patch.object(os, 'fchmod', getattr(os, 'fchmod', lambda *_: None), create=True), \
                        patch.object(O.VR, 'apply'), patch.object(K, 'connect_request', return_value=(client, '/fixture')):
                    emitted = self.held_start(args)
                self.assertEqual(attempts, ['file'] if failed_sync == 'file' else ['file', 'directory'])
                self.assertEqual((emitted['status'], emitted['diagnosisSaved'], emitted['doNotRerunApply']),
                                 ('HELD', False, True))
                raw = result.read_bytes()
                residue = json.loads(raw)
                self.assertEqual((residue['reason'], residue['dockerStartRequests'], residue['partialReadbackTimeout']),
                                 ('R3_PARTIAL_START_DENIED', 1, True))
                self.assertFalse(residue['partialObservation']['southbound']['postAttempted'])
                s.api.current['bridge']['nftables'][1]['table']['handle'] -= 1
                retry = self.held_start(args)
                self.assertEqual((retry['status'], retry['doNotRerunApply'], retry['dockerStartRequests']),
                                 ('HELD', True, 0))
                self.assertEqual(result.read_bytes(), raw)

    def test_a3_34_response_collected_while_second_gate_denies(self):
        for status in (204, 503):
            with self.subTest(status=status), self.start_plan() as (s, args, _):
                now = [0.]
                def advance(seconds):
                    now[0] += seconds
                clock = SimpleNamespace(monotonic=lambda: now[0], sleep=advance)
                collected = threading.Event()
                first, second = MagicMock(), MagicMock()
                reply = first.getresponse.return_value
                reply.__enter__.return_value.status = status
                reply.__exit__.side_effect = lambda *_: collected.set()
                def receive():
                    now[0] = .1
                    return reply
                first.getresponse.side_effect = receive
                gate = K.submission_gate
                @contextmanager
                def slow_gate(*context):
                    with gate(*context) as verify:
                        def check():
                            if first.request.called:
                                self.assertTrue(collected.wait(5))
                                now[0] = 1.1
                                s.api.current['bridge']['nftables'][1]['table']['handle'] += 1
                            verify()
                        yield check
                with patch.object(O, 'time', clock), patch.object(K, 'time', clock), \
                        patch.object(K, 'submission_gate', slow_gate), patch.object(O.VR, 'apply'), \
                        patch.object(K, 'connect_request', side_effect=[(first, '/first'), (second, '/second')]):
                    emitted = self.held_start(args)
                report = json.loads((Path(args.output_directory) / 'result.json').read_bytes())
                self.assertEqual(report, emitted)
                self.assertEqual((report['status'], report['reason']), ('HELD', 'R3_PARTIAL_START_DENIED'))
                self.assertEqual(first.sock.response_deadline, 1.)
                self.assertEqual(report['deniedRequest'], {'role': 'southbound', 'reason': g.SEAL_DRIFT})
                self.assertEqual(report['requestErrors'], [] if status == 204 else
                                 [{'role': 'adapter', 'reason': 'R3_DOCKER_REQUEST_FAILED'}])
                second.request.assert_not_called()

    def test_a3_34_each_post_deadline_starts_at_its_send(self):
        for first_end, second_end, failures in ((.99, 1.10, []), (.99, 1.26, ['southbound']),
                                                (1.26, 1.1, ['adapter'])):
            with self.subTest(first_end=first_end, second_end=second_end), self.start_plan() as (_, args, plan):
                # Read completion advances only the clock of the corresponding
                # worker. The second send occurs at .25 regardless of read order.
                clock = threading.local()
                clock.now = 0.
                clients = [MagicMock(), MagicMock()]
                reading = threading.Barrier(2, timeout=5)
                def first_send(*args, **kwargs):
                    clock.now = .25
                clients[0].request.side_effect = first_send
                def response(end):
                    reading.wait()
                    clock.now = end
                    reply = MagicMock()
                    reply.__enter__.return_value.status = 204
                    return reply
                clients[0].getresponse.side_effect = lambda: response(first_end)
                clients[1].getresponse.side_effect = lambda: response(second_end)
                report = dict(O.COUNTERS)
                with patch.object(O, 'time', SimpleNamespace(monotonic=lambda: getattr(clock, 'now', .25))), \
                        patch.object(K, 'connect_request', side_effect=[(c, '/fixture') for c in clients]), \
                        patch.object(O.VR, 'apply'), patch.object(O, 'poll'):
                    if failures:
                        with self.assertRaisesRegex(O.A.OperationDenied, 'R3_DOCKER_REQUEST_FAILED'):
                            O.apply(args, plan, report)
                    else:
                        O.apply(args, plan, report)
                clients[0].sock.settimeout.assert_called_once_with(.75)
                clients[1].sock.settimeout.assert_called_once_with(1.)
                self.assertEqual([c.sock.response_deadline for c in clients], [1., 1.25])
                self.assertEqual(report['requestErrors'],
                                 [{'role': r, 'reason': 'R3_DOCKER_REQUEST_TIMEOUT'} for r in failures])

    def test_a3_34_g3_poll_budgets_each_nft_read_under_lock(self):
        with self.start_plan() as (s, args, plan):
            now = [0.]
            def advance(seconds):
                now[0] += seconds
            clock = SimpleNamespace(monotonic=lambda: now[0], sleep=advance)
            reads = []
            run = K.subprocess.run
            def nft(argv, **kwargs):
                reads.append((argv[3:], kwargs['timeout']))
                advance(.25)
                return run(argv, **kwargs)
            with patch.object(O, 'time', clock), patch.object(K, 'time', clock), \
                    patch.object(K.subprocess, 'run', nft):
                latest = O.observe(args, output_exists=True, deadline=1.)
            name = s.owner['kernel']['tableName']
            self.assertEqual(reads, [(['tables'], 1.), (['table', 'inet', name], .75),
                                     (['table', 'bridge', name], .5)])
            self.assertEqual(latest['leaseKernel'], plan['observation']['leaseKernel'])

    def test_a3_34_g3_poll_requires_completed_observation_within_window(self):
        from test_semantic_provider_r3_operate import arguments, observation, successful
        args = arguments()
        before = observation()
        before['leaseKernel'] = {'generation': 3, 'sealSha256': HEAD}
        after = successful('start', before)
        after['leaseKernel'] = before['leaseKernel']
        self.assertTrue(O.reached(args, before, after))
        for end in (.99, 1.01):
            with self.subTest(end=end):
                now = [0.]
                def observe(*_, deadline, **kwargs):
                    self.assertEqual(deadline, 1.)
                    now[0] = end
                    return after
                report = {}
                with patch.object(O, 'time', SimpleNamespace(monotonic=lambda: now[0])), \
                        patch.object(O, 'observe', observe):
                    if end < 1:
                        O.poll(args, before, report)
                    else:
                        with self.assertRaisesRegex(O.A.OperationDenied, 'R3_READBACK_TIMEOUT'):
                            O.poll(args, before, report)
                self.assertEqual(report['lastObservation'], after)

    def test_a3_34_header_fragments_share_the_post_deadline(self):
        with K.EngineSocket() as sock, patch.object(K.socket.socket, 'recv_into', return_value=1) as recv:
            sock.response_deadline = 5
            with patch.object(K.time, 'monotonic', side_effect=[1, 4.75, 5]):
                with sock.makefile('rb', buffering=0) as stream:
                    buffer = bytearray(1)
                    self.assertEqual(stream.readinto(buffer), 1)
                    self.assertEqual(sock.gettimeout(), 4)
                    self.assertEqual(stream.readinto(buffer), 1)
                    self.assertEqual(sock.gettimeout(), .25)
                    with self.assertRaises(TimeoutError):
                        stream.readinto(buffer)
            self.assertEqual(recv.call_count, 2)

    def test_a3_34_generation_writer_contends_during_both_posts(self):
        from tools.semantic_lease_kernel_migration import native
        from contextlib import ExitStack
        with self.start_plan() as (s, args, plan):
            owner = s.owner
            writer = SimpleNamespace(owner=owner,
                                     args=SimpleNamespace(lock=owner['commonLockFile'], install_root=s.root),
                                     runtime=lambda: ({'candidates': O.ROLES}, 12))
            @contextmanager
            def operation_locks(root, candidates):
                with ExitStack() as stack:
                    for role in candidates:
                        stack.enter_context(exclusive(s.api, root / (role + '.lock')))
                    yield
            def send(*_args, **_kwargs):
                with self.assertRaises(PermissionError if os.name == 'nt' else BlockingIOError):
                    with native.Native.locks(writer):
                        self.fail('generation writer entered during POST')
            client = MagicMock()
            client.request.side_effect = send
            client.getresponse.return_value.__enter__.return_value.status = 204
            report = dict(O.COUNTERS)
            with patch.object(s.api, 'lock', lambda p: exclusive(s.api, p)), \
                    patch.object(B, 'lock', side_effect=s.api.lock), \
                    patch.object(native.I, 'operation_locks', operation_locks), \
                    patch.object(B, 'directory_lock', side_effect=s.api.directory_lock), \
                    patch.object(K, 'connect_request', return_value=(client, '/fixture')), \
                    patch.object(O.VR, 'apply'), patch.object(O, 'poll'):
                O.apply(args, plan, report)
                with native.Native.locks(writer):
                    self.assertIn('common.lock', s.api.held)
            self.assertEqual((report['dockerStartRequests'], client.request.call_count), (2, 2))

    def test_a3_34_issuer_succeeds_before_admission_or_after_both_posts(self):
        from test_semantic_provider_operation_issuance import issue
        for issuer_first in (True, False):
            with self.subTest(issuer_first=issuer_first), self.start_plan() as (s, args, plan):
                chain = s.root / 'authorization'
                previous = s.runtime.authorization_head()
                successor = {**previous, 'sequence': 13, 'sha256': 'e' * 64}
                def current(*_):
                    return successor if (chain / '13.signature.json').exists() else previous
                s.runtime.authorization_head = current
                def publish():
                    with issue.publication_lock(s.root, previous, B.canonical(s.owner),
                                                s.coordinator['ownerConfiguration']):
                        Fake.write_once(s.api, chain / '13.json', B.canonical(successor['authorization']))
                        Fake.write_once(s.api, chain / '13.signature.json', B.canonical({'signature': 'fixture'}))
                gate = K.submission_gate
                @contextmanager
                def admission(*context):
                    if issuer_first:
                        publish()
                    with gate(*context) as check:
                        yield check
                def send(*_args, **_kwargs):
                    with self.assertRaises(PermissionError if os.name == 'nt' else BlockingIOError):
                        publish()
                    self.assertEqual(current(), previous)
                client = MagicMock()
                client.request.side_effect = send
                client.getresponse.return_value.__enter__.return_value.status = 204
                report = dict(O.COUNTERS)
                with patch.object(s.api, 'lock', lambda p: exclusive(s.api, p)), \
                        patch.object(issue.boot, 'lock', side_effect=s.api.lock), \
                        patch.object(K, 'submission_gate', admission), patch.object(O.VR, 'apply'), \
                        patch.object(K, 'connect_request', return_value=(client, '/fixture')), patch.object(O, 'poll'):
                    if issuer_first:
                        with self.assertRaisesRegex(O.A.OperationDenied, 'AUTHORIZATION_CHANGED'):
                            O.apply(args, plan, report)
                    else:
                        O.apply(args, plan, report)
                        publish()
                expected = 0 if issuer_first else 2
                self.assertEqual((client.request.call_count, report['dockerStartRequests']), (expected, expected))
                self.assertEqual(current(), successor)

    def test_a3_34_signed_files_need_file_and_directory_sync_before_post(self):
        for suffix in ('json', 'signature.json'):
            for failure in ('file', 'directory'):
                with self.subTest(suffix=suffix, failure=failure), self.start_plan() as (s, args, plan):
                    path = s.root / 'authorization' / ('12.' + suffix)
                    raw = path.read_bytes()
                    path.unlink()
                    trace = PublicationTrace(('write', path.name, 'after'))
                    with trace.instrument(s.api), self.assertRaises(Cut):
                        s.api.write_once(path, raw)
                    client = MagicMock()
                    report = dict(O.COUNTERS)
                    with self.fail_confirmation(s, path, failure), patch.object(O.VR, 'apply'), \
                            patch.object(K, 'connect_request', return_value=(client, '/fixture')), \
                            self.assertRaisesRegex(O.A.OperationDenied, 'G3_EVIDENCE'):
                        O.apply(args, plan, report)
                    client.request.assert_not_called()
                    self.assertEqual((path.read_bytes(), report['dockerStartRequests']), (raw, 0))

    def test_a3_35_pointer_rename_and_repeated_sync_failure_before_start_or_tick(self):
        for active in (False, True):
            with self.subTest(active=active):
                s = self.scenario()
                if active:
                    s.ready()
                folder = s.root / 'selection'
                folder.mkdir()
                path = folder / 'bootPointer'
                s.coordinator['bootPointer'] = str(path)
                raw = (s.root / 'pointer').read_bytes()
                Fake.write_once(s.api, path, b'{}')
                sync = s.api.sync
                def crash(directory):
                    if directory == folder and path.read_bytes() == raw:
                        raise Cut()
                    sync(directory)
                with s.api.lock(s.coordinator['commonLockPath']), patch.object(s.api, 'sync', crash), self.assertRaises(Cut):
                    Fake.cas(s.api, path, b'{}', raw)
                action = s.tick if active else s.operate
                journal = s.journal()
                for failure in ('file', 'directory'):
                    with self.fail_confirmation(s, path, failure), self.assertRaises((OSError, O.A.OperationDenied)):
                        action()
                    self.assertEqual(path.read_bytes(), raw)
                    self.assertEqual(s.journal(), journal)
                    self.assertEqual(s.batch_count, 0)
                with self.fail_confirmation(s, path, None):
                    action()
