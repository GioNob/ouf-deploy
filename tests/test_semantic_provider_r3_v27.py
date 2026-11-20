"""R-002. Replay the emitted supervisor from closed ingress with real operation signatures."""
import builtins
from contextlib import ExitStack, contextmanager, nullcontext
from copy import deepcopy
import errno
from functools import lru_cache
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_semantic_provider_r3_v25 as v25
import test_semantic_provider_r3_v16_adapter as v16
from tools.semantic_authority_mandates import mandates
from tools.semantic_provider_r3 import ingress_memo_overlay_v27 as overlay

C = v25.C
ROOT = Path(__file__).resolve().parents[1]
OPENSSL = shutil.which('openssl')


@contextmanager
def exclusive_writer(path):
    program = """import fcntl, os, select, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
print('locked', flush=True)
sys.exit(0 if select.select([sys.stdin], [], [], 10)[0] else 1)
"""
    with subprocess.Popen([sys.executable, '-I', '-B', '-c', program, str(path)],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE) as writer:
        try:
            if writer.stdout.readline().strip() != b'locked':
                raise AssertionError('exclusive writer failed to acquire flock')
            yield
        finally:
            writer.stdin.close()
            if writer.wait(timeout=12):
                raise AssertionError('writer exited before release')


@lru_cache
def temporal_inputs():
    inputs, _, _ = v25.fixture(30)
    # A DNS answer can outlive the 30 s per-flow kernel cap. Generate the
    # corresponding synthetic owner, journal and receipts with their producer.
    base = v16.V12.F.fixture
    def dns_profile(version):
        original = base(version)
        owner = C.document(original['files']['coordinator'])
        owner['dns']['maxLeaseSeconds'] = 60
        original['files']['coordinator'] = C.canonical(owner)
        return original
    with patch.object(v16.V12.F, 'fixture', dns_profile):
        migration = v16.v16_fixture()[0]['files']
    files = {**inputs['files'], **{k: migration[k] for k in ('coordinator', 'coordinationJournal',
             'migrationPlan', 'migrationReceipt', 'generationReceipt', 'bootPointer')}}
    settings = C.document(files['settings'])
    settings['coordinatorBinding'] = C.document(migration['settings'])['coordinatorBinding']
    settings['supervisorLimits']['heartbeatSeconds'] = 5
    files['settings'] = C.canonical(settings)
    return dict(inputs, files=files)


@lru_cache
def fixture(version):
    inputs = temporal_inputs()
    files = dict(inputs['files'])
    files['leaseRenewal'] = (ROOT / f'ops/vps/r3-lease-renewal-v{version}.json').read_bytes()
    inputs = dict(inputs, files=files)
    return inputs, C.compose(inputs, version, sequence=version, supersedes=C.sha(v25.fixture(30)[2]['authorization']))


class Chain:
    def __init__(self, root, version=27):
        self.root = root
        self.directory = root / 'authorizations'
        self.directory.mkdir(mode=0o700)
        self.ledger = root / 'ledger'
        self.ledger.mkdir(mode=0o700)
        self.openssl = Path(OPENSSL).resolve(strict=True)
        self.ssl = dict(path=str(self.openssl), sha256=C.sha(self.openssl.read_bytes()),
                        version=self.run('version').decode().split()[1])
        self.key = root / 'temporary.pem'
        self.run('genpkey', '-algorithm', 'Ed25519', '-out', self.key)
        public = self.run('pkey', '-in', self.key, '-pubout', '-outform', 'DER')
        assert public.startswith(mandates.DER_PREFIX) and len(public) == len(mandates.DER_PREFIX) + 32
        self.payload = C.document(fixture(version)[1]['authorization'])
        self.now = self.payload['issuedAt']
        self.scope = dict(installationRef='fixture-install', entityRef='fixture-entity', issuerRef='fixture-issuer')
        self.payload.update(self.scope)
        binding = dict(path=str(root / 'unused'), sha256='0' * 64)
        self.signer = dict(keyRef='fixture', issuerRef=self.scope['issuerRef'], roles=[C.A.ROLE],
                           publicKey=public[-32:].hex(), notBefore=self.now-1, expiresAt=self.now+100, state='ACTIVE')
        anchor = dict(schema=mandates.B1B2_ANCHOR_SCHEMA, installationRef=self.scope['installationRef'],
                      entityRef=self.scope['entityRef'], basePolicy=binding, authorityProfile=binding, keys=[self.signer])
        path = root / 'anchor.json'
        self.write(path, C.canonical(anchor))
        self.anchor = dict(path=str(path), sha256=C.sha(path.read_bytes()))
        self.count, self.digest = 0, None
        for _ in range(26):
            self.append()

    @staticmethod
    def write(path, raw):
        path.write_bytes(raw)
        path.chmod(0o600)

    def run(self, *args):
        return subprocess.run([self.openssl, *args], capture_output=True, check=True, timeout=8).stdout

    def append(self, decision='OPERATE'):
        self.count += 1
        raw = C.canonical(dict(self.payload, sequence=self.count, decision=decision, supersedes=self.digest))
        self.digest = C.sha(raw)
        header = dict(schema=C.A.SIGNATURE_SCHEMA, algorithm='Ed25519', keyRef='fixture', role=C.A.ROLE,
                      payloadHash=self.digest, **self.scope)
        frame = self.root / 'frame'
        self.write(frame, C.A.signing_bytes(raw, header))
        signature = self.run('pkeyutl', '-sign', '-rawin', '-inkey', self.key, '-in', frame)
        self.write(self.directory / f'{self.count}.json', raw)
        self.write(self.directory / f'{self.count}.signature.json', C.canonical(dict(header, signature=signature.hex())))

    def revoke(self):
        self.now += 1  # Issuance was valid. The later revocation is independently effective.
        record = dict(schema=mandates.LEDGER_SCHEMA, generation=1, anchor=self.anchor, previousSha256=None,
                      issuedAt=self.now, **self.scope, preconditions=dict.fromkeys(mandates.PRECONDITION_FLAGS, True),
                      mandates=[{k: self.signer[k] for k in mandates.MANDATE_FIELDS}])
        record['mandates'][0]['state'] = 'REVOKED'
        record['preconditions']['evidenceSha256'] = 'a' * 64
        self.write(self.ledger / '1.json', C.canonical(record))

    def configure(self, cfg):
        return dict(cfg, **self.scope, anchorBinding=self.anchor, mandateRoot=str(self.ledger), opensslBinding=self.ssl,
                    authorizationRoot=str(self.directory))


class Composition(unittest.TestCase):
    def test_overlay_is_anchored_and_preserves_line_endings(self):
        inputs, _ = fixture(27)
        with patch.object(overlay, 'sources_v27', wraps=overlay.sources_v27) as build:
            C.compose(inputs, 27, sequence=27, supersedes='a' * 64)
        sources, mapping = build.call_args.args
        emitted = overlay.sources_v27(sources, mapping)
        crlf = {p: raw.replace(b'\n', b'\r\n') for p, raw in sources.items()}
        self.assertEqual(overlay.sources_v27(crlf, mapping),
                         {p: raw.replace(b'\n', b'\r\n') for p, raw in emitted.items()})
        path = mapping[overlay.CONTINUOUS]
        with self.assertRaisesRegex(C.A.OperationDenied, overlay.DRIFT):
            overlay.sources_v27(sources | {path: sources[path].replace(b'def renew(', b'def other(')}, mapping)

    def test_predecessor_source_bytes_and_policy(self):
        # Fingerprint of *all* emitted source bytes at f3473e07, before v27.
        for version in (25, 26):
            docs = fixture(version)[1]['documents']
            hashes = {p.split('/source/')[1]: C.sha(b) for p, b in docs.items() if '/source/' in p}
            self.assertEqual(C.sha(C.canonical(hashes)), 'e9699837663f16f326f469b10385801da2d84fa7345bb0de2e1dc482b38e7952')
        files = fixture(27)[0]['files']
        self.assertEqual(files['leaseRenewal'], fixture(25)[0]['files']['leaseRenewal'])
        self.assertEqual(files['leaseRenewal'], C.canonical(C.document(files['leaseRenewal'])))

    def test_composition_requires_a_possible_progress_window(self):
        inputs, result = fixture(27)
        def policy(version):
            docs = fixture(version)[1]['documents']
            return C.contract_module(docs[f'versions/{version}/source/' + C.LEASE_RENEWAL_TARGET], 'budget')
        config = C.document(result['documents']['versions/27/supervisor/configuration.json'])
        renewal = dict(config['leaseRenewal'], semanticTickBudgetSeconds=2.5)
        owner = C.document(inputs['files']['coordinator'])
        dns = policy(27).dns_profile(owner, renewal)
        flows = [dict(flow, leaseSeconds=24) for flow in owner['kernel']['providerFlows']]
        args = renewal, dns, flows, config['driverBudgetSeconds']
        policy(26).budgets(*args)
        with self.assertRaisesRegex(ValueError, 'R3_LEASE_RENEWAL_BUDGET_INCOMPATIBLE'):
            policy(27).budgets(*args)


class Replay(unittest.TestCase):
    def start(self, version, *, disable=False, lease_cost=False):
        stack = self.enterContext(ExitStack())
        chain = Chain(Path(stack.enter_context(tempfile.TemporaryDirectory())), version)
        case = v25.v24.Renewal()
        case.inputs, case.result = fixture(version)
        case.retained = v25.v24.v20.V12.fixture()[2]
        stack.callback(case.doCleanups)
        tables, peer = v25.IngressTables(), v25.PeerFixture()
        stack.enter_context(patch.object(v25.live, 'semantic_kernel'))
        self.chain, self.tables, self.peer = chain, tables, peer
        self.calls = []
        command_ms = iter(())
        # Deterministic costs within the observed 14--22 ms per command.
        def command_cost(n=1):
            nonlocal command_ms
            for _ in range(n):
                ms = next(command_ms, None)
                if ms is None:
                    command_ms = iter((18, 22))
                    ms = 14
                case.advance(ms / 1000)

        def runtime(sup, configuration):
            original = sup.bind_semantic_gate
            advance = case.advance
            limit = None
            def timed_advance(seconds):
                if limit is not None and case.clock() + seconds >= limit:
                    advance(max(0, limit - case.clock()))
                    raise sup.SemanticDeadline()
                advance(seconds)
            @contextmanager
            def phase(end, clock):
                nonlocal limit
                limit = end
                try:
                    with v25.virtual_phase(end, clock, sup.SemanticDeadline):
                        yield
                finally:
                    limit = None
            case.advance = timed_advance
            m = C.contract_module(case.inputs['sources'][C.MANDATES], 'v27_mandates')
            m.Path = Path
            # The portable fixture substitutes POSIX custody at the file boundary.
            # Both inventories, the real ledger and the real signature verifier run.
            a = sup.authorization
            a.os = SimpleNamespace(lstat=lambda path: SimpleNamespace(st_mode=0o40700, st_uid=0),
                                   listdir=os.listdir)
            a.private_file = Path.read_bytes
            m.ancestors = lambda p: None
            m.private_bytes = lambda path, *args: path.read_bytes()
            m.ledger_directory = Path.lstat
            m.ENV = dict(os.environ, OPENSSL_CONF=os.devnull)
            def executable(auth):
                auth.budget.check()
                self.assertEqual(C.sha(chain.openssl.read_bytes()), auth.openssl_binding['sha256'])
                return str(chain.openssl)
            m.MandateAuthenticator.executable = executable
            def run(argv, **kwargs):
                self.calls.append(argv[1])
                if argv[1] == 'pkeyutl':
                    case.advance(.025)
                return subprocess.run(argv, **kwargs)
            m.subprocess = SimpleNamespace(run=run, DEVNULL=subprocess.DEVNULL, TimeoutExpired=subprocess.TimeoutExpired)
            spec = configuration.value['semanticIngress']
            footprint = v25.live.semantic_digest({f: tables.listing(f, spec['table']) for f in ('bridge', 'inet')})
            driver = C.canonical({'profile': {'expectedFootprint': footprint,
                'policy': {'tableName': spec['table'], 'flows': [{'peerIngress': {'kind': 'SEMANTIC_PROFILE',
                                                                             'declaration': spec['profile']}}]}}})
            rows = {role['containerId']: dict(epoch=7, state='STARTED', generation=dict(pid=7, startTicks=9),
                                              authorizationSha256=chain.digest, driverHash=C.sha(driver))
                    for role in chain.payload['roles'].values()}
            self.rows = rows
            def command(binding, argv, raw=None, *, deadline):
                self.assertTrue(case.locked)
                command_cost()
                return tables.command(argv, spec['table'], raw)
            sup.semantic_command = command
            def observe(*_):
                command_cost(4)
                return peer.observe(), peer.row
            sup.semantic_observe = observe
            def link(p, cmds, generation, run):
                command_cost(2)
                return peer.observe({'generation': generation})
            def bind(cfg, coordinator, guards, read):
                guards.cfg = chain.configure(cfg)
                guards.mandates, guards.clock = m, lambda: chain.now
                guards.boot, guards.live = lambda: 'fixture', lambda *args: True
                guards.current = lambda root, cid: rows[cid]
                self.guards = guards
                start = case.clock()
                guards.fixed = guards.scope_guard()
                self.cold = case.clock() - start, self.calls.count('pkeyutl'), self.calls.count('version')
                case.guard = guards.scope_guard
                original(cfg, coordinator, guards, lambda path, digest: driver,
                         phase=phase,
                         link_observer=link)
                if disable:
                    coordinator.semantic_tick = lambda *_: None
            if version >= 27:
                self.writer_locks = sup.ingress_writer_locks
                sup.ingress_writer_locks = lambda *_: nullcontext()
            with patch.object(sup, 'bind_semantic_gate', bind):
                return sup.runtime(configuration)
        # A healthy reply leaves a ~2 s ordinary window at startup.
        query = case.query
        initial = True
        def first_query(*args, **kwargs):
            nonlocal initial
            if initial:
                case.query_outcomes.append(31)
                initial = False
            return query(*args, **kwargs)
        case.query = first_query
        if lease_cost:
            # Each tables()/ownership check reads both nft families. Sample
            # at the start of the read and deliver the result at its end.
            def costed(fn, seconds):
                def invoke(*args, **kwargs):
                    result = fn(*args, **kwargs)
                    case.advance(seconds)
                    return result
                return invoke
            case.tables = costed(case.tables, .036)
            case.verify = costed(case.verify, .036)
            case.run_nft = costed(case.run_nft, .018)
        case.native_runtime = runtime
        case.setUp()
        return case

    def wait_and_renew(self, case):
        scheduled = case.scheduled
        case.advance(max(0, scheduled['wakeMonotonic'] - case.clock()))
        self.assertFalse(case.locked)
        before = case.clock()
        end = scheduled['leaseDeadlineMonotonic']
        result = case.renew()
        self.assertEqual(result['reason'], 'RENEWED')
        self.assertLess(case.clock(), end)
        self.assertTrue(case.coordination['leaseAuthorized'])
        self.assertNotIn('QUIESCED', case.lease_states)
        case.scheduled = case.supervisor.tick()
        self.assertEqual(case.scheduled['state'], 'ACTIVE')
        return before, case.clock()

    @contextmanager
    def writer_error(self, case, *, at_open=False):
        # Exercise the emitted lock acquisition even on hosts without fcntl.
        # Only the descriptor and flock syscalls are synthetic.
        closed = []
        def attempted(*_):
            raise BlockingIOError(errno.EWOULDBLOCK, 'busy')
        def flock(fd, flags):
            self.assertEqual((fd, flags), (7, 1 | 4))
            attempted()
        descriptors = SimpleNamespace(O_RDONLY=0, O_NOFOLLOW=1, O_NONBLOCK=2,
            open=attempted if at_open else lambda *_: 7, close=closed.append)
        with patch.dict(sys.modules, fcntl=SimpleNamespace(LOCK_SH=1, LOCK_NB=4, flock=flock)), \
             patch.multiple(case.sup, ancestors=lambda _: None, os=descriptors,
                            ingress_writer_locks=self.writer_locks):
            yield
        self.assertEqual(closed, [] if at_open else [7])

    def check_busy_tick(self, case):
        self.assertTrue(all(self.tables.members.values()))
        lease = deepcopy((case.coordination, case.elements, case.commands, case.journal.read()))
        with patch.object(self.tables, 'command', wraps=self.tables.command) as commands:
            row = case.supervisor.ingress_before_wait(case.scheduled, case.stop)
        self.assertIs(row, case.scheduled)
        self.assertEqual(row['state'], 'ACTIVE')
        self.assertTrue(case.supervisor.active_here)
        self.assertEqual((case.coordination, case.elements, case.commands, case.journal.read()), lease)
        self.assertEqual(case.c.semantic_result['outcome'], 'CLOSED')
        self.assertLessEqual(case.c.semantic_result['durationMs'],
                             case.cfg['leaseRenewal']['semanticCloseReserveSeconds'] * 1000)
        self.assertIsNone(case.c.semantic_epoch())
        self.assertFalse(any(self.tables.members.values()))
        reads = [args for (args, _, _), _kwargs in commands.call_args_list if 'set' in args]
        self.assertCountEqual([(args[-3], args[-1]) for args in reads], self.tables.members.keys())
        self.assertFalse(case.locked)

    @unittest.skipUnless(sys.platform == 'linux' and os.getuid() == os.getgid() == 0,
                         'requires Linux and root-owned lock paths')
    def test_exclusive_writer_in_another_process(self):
        import fcntl  # Save the native module before the portable bootstrap substitutes it.
        case = self.start(27)
        with tempfile.TemporaryDirectory(dir='/var/lib') as directory:
            root = Path(directory)
            auth = root / 'authorization'
            auth.mkdir(mode=0o700)
            paths = []
            for role in self.guards.fixed.values():
                cid = root / role['containerId']
                cid.mkdir(mode=0o700)
                paths.append(cid / 'operation.lock')
                paths[-1].touch(mode=0o600)
            def real_locks(cfg, guards):
                return self.writer_locks(dict(cfg, registryRoot=str(root), authorizationRoot=str(auth)), guards)
            with patch.dict(sys.modules, fcntl=fcntl), patch.multiple(case.sup, Path=Path,
                                                                     ingress_writer_locks=real_locks):
                self.wait_and_renew(case)
                case.supervisor.ingress_before_wait(case.scheduled, case.stop)
                for path in (max(paths), auth):
                    with self.subTest(lock=path.name):
                        self.wait_and_renew(case)
                        with exclusive_writer(path):
                            self.check_busy_tick(case)
                        self.wait_and_renew(case)
                        case.supervisor.ingress_before_wait(case.scheduled, case.stop)
                        self.assertEqual(case.c.semantic_result['outcome'], 'VERIFIED')

    def test_would_block_from_open_remains_fatal(self):
        case = self.start(27)
        self.wait_and_renew(case)
        with self.writer_error(case, at_open=True):
            row = case.supervisor.ingress_before_wait(case.scheduled, case.stop)
        self.assertEqual(row['state'], 'BLOCKED')
        self.assertEqual(case.c.semantic_result['outcome'], 'CLOSED')

    def test_busy_writer_unverified_close_blocks(self):
        case = self.start(27)
        self.wait_and_renew(case)
        command = case.sup.semantic_command
        def missing_readback(binding, args, raw=None, *, deadline):
            # Fail the reserved readback. The subsequent pause has its own
            # independent quiescence verification outside the tick deadline.
            if deadline is not None and 'set' in args:
                return b'{"nftables":[]}'
            return command(binding, args, raw, deadline=deadline)
        with self.writer_error(case), patch.object(case.sup, 'semantic_command', missing_readback):
            row = case.supervisor.ingress_before_wait(case.scheduled, case.stop)
        self.assertEqual((row['state'], row['reason']), ('BLOCKED', 'R3_SEMANTIC_CLOSE_UNVERIFIED'))
        self.assertEqual(case.c.semantic_result['outcome'], row['reason'])
        self.assertFalse(case.locked)

    def test_old_failures_and_first_committed_opening(self):
        for version, expected in ((25, 'CLOSED'), (26, 'DEFERRED'), (27, 'VERIFIED')):
            with self.subTest(version=version), ExitStack() as stack:
                case = self.start(version, lease_cost=True)
                stack.callback(self.doCleanups)
                self.assertFalse(any(self.tables.members.values()))
                if version == 27:
                    self.assertIsNone(case.c.semantic_epoch())
                    self.assertEqual(self.cold[1:], (26, 26))
                    self.assertAlmostEqual(self.cold[0], .65)
                    self.calls.clear()
                    self.wait_and_renew(case)
                    row = case.supervisor.ingress_before_wait(case.scheduled, case.stop)
                    self.assertEqual(row['state'], 'ACTIVE')
                    self.assertEqual(self.calls, [])
                    self.assertIsNotNone(case.c.semantic_epoch())
                    self.assertEqual(self.tables.members['bridge', 'semantic_port'], [self.peer.index])
                    for family in ('bridge', 'inet'):
                        self.assertEqual(self.tables.members[family, 'semantic_open'], [self.peer.ip])
                    self.assertGreaterEqual(case.c.semantic_window_ms, 950)
                    self.assertLess(case.c.semantic_result['durationMs'], 700)
                    self.assertLess(case.clock() - 100, case.cfg['leaseRenewal']['semanticFullObservationSeconds'])
                    status = []
                    service = v25.Consumers.service(case, case.c, writer=lambda _, value: status.append(value))
                    service.status('ACTIVE')
                    self.assertEqual(status[-1]['lastSemanticWindowMs'], case.c.semantic_window_ms)
                print(f"v{version} {case.c.semantic_result} startup pkeyutl={self.cold[1]}", flush=True)
                self.assertEqual(case.c.semantic_result['outcome'], expected)

    def test_renewal_times_match_without_ingress(self):
        def timeline(disable):
            case = self.start(27, disable=disable, lease_cost=True)
            case.apply_delay = .28
            events, durations, opportunities = [], [], [case.clock()]
            for i in range(14):
                # Install a short, still complete lease in both runs. Its
                # zero wait is known before deciding about Semantic work.
                case.query_outcomes.append(24 if i == 7 else 60)
                events.extend(self.wait_and_renew(case))
                if i == 4 and not disable:
                    case.release = case.clock() + .19
                before = case.clock()
                busy = i in (2, 9) and not disable
                if busy:
                    with self.writer_error(case):
                        self.check_busy_tick(case)
                else:
                    case.supervisor.ingress_before_wait(case.scheduled, case.stop)
                durations.append(case.clock() - before)
                if not disable:
                    expected = 'CLOSED' if busy else 'DEFERRED' if i == 7 else 'VERIFIED'
                    self.assertEqual(case.c.semantic_result['outcome'], expected)
                    if i == 7:
                        self.assertEqual(case.scheduled['waitSeconds'], 0)
                    else:
                        self.assertGreaterEqual(case.c.semantic_window_ms, 950)
                        if not busy:
                            opportunities.append(before)
                    self.assertLess(durations[-1], .7)
            self.assertEqual(case.supervisor.renewals, 14)
            # A short cached DNS answer requires a fresh collection while the
            # previous lease is still complete in both families.
            previous_end = case.scheduled['leaseDeadlineMonotonic']
            case.query_outcomes.extend((16, 60))
            query = case.dns.observe_many
            def mixed(*args, **kwargs):
                rows = query(*args, **kwargs)
                if rows[0]['minimumObservedTtlSeconds'] == 16:
                    rows[1].update(minimumObservedTtlSeconds=30, expiresMonotonic=case.clock()+30)
                return rows
            with patch.object(case.dns, 'observe_many', mixed):
                self.wait_and_renew(case)
            event, ready, _, due, collected = case.journal.read()['lastCacheRollover']
            self.assertEqual(event, 'cacheRenewed')
            self.assertGreaterEqual(collected, due)
            self.assertLess(ready, previous_end)
            events.extend((collected, ready))
            case.supervisor.ingress_before_wait(case.scheduled, case.stop)
            self.assertEqual(self.calls.count('pkeyutl'), 26)
            if not disable:
                self.assertIsNotNone(case.journal.read()['lastSemanticWindowMs'])
                self.assertLess(max(b-a for a, b in zip(opportunities, opportunities[1:])),
                                case.cfg['leaseRenewal']['semanticFullObservationSeconds'])
                print('warm first/steady/contended seconds', *(round(durations[i], 3) for i in (0, 1, 4)))
            self.doCleanups()
            return events
        baseline, actual = timeline(True), timeline(False)
        self.assertTrue(all(abs(a-b) <= .05 for a, b in zip(actual, baseline)), (actual, baseline))
        # Regular wakes are five seconds plus the common publication cost.
        cadence = actual[6] - actual[4]
        self.assertAlmostEqual(cadence, 5.5, delta=.2)
        print(f'ordinary cadence {cadence:.3f}s, maximum scheduling difference '
              f'{max(abs(a-b) for a,b in zip(actual, baseline)):.3f}s')

    def test_serve_consumes_commit_once_after_mandatory_observation(self):
        case = self.start(27)
        ticks = []
        run = case.c.semantic_tick
        observed = []
        def observe(row):
            case.advance(.11)
            observed.append((case.clock(), row['renewals']))
        def tick(wake, end, journal):
            self.assertEqual(observed[-1], (case.clock(), case.supervisor.renewals))
            self.assertEqual(case.journal.read()['reason'], 'RENEWED')
            self.assertFalse(case.locked)
            self.assertLess(case.clock(), end)
            run(wake, end, journal)
            ticks.append((case.supervisor.renewals, wake, case.c.semantic_result['outcome']))
        def after_wait():
            if ticks:
                self.assertAlmostEqual(case.clock(), ticks[-1][1])
            case.stopped = len(ticks) == 3
        case.journal.invocation = nullcontext
        case.after_wait = after_wait
        case.c.semantic_tick = tick
        case.supervisor.serve(case.stop, observe)
        self.assertEqual([(n, outcome) for n, _, outcome in ticks], [(i, 'VERIFIED') for i in (1, 2, 3)])

    def test_cache_due_then_new_commit(self):
        case = self.start(27)
        case.test_collect_on_time_while_last_flow_drains()
        # The cacheTarget branch collected exactly once at cache_due.
        scheduled = case.supervisor.tick()
        self.assertIsNotNone(scheduled['semanticSlot'])
        case.supervisor.ingress_before_wait(scheduled, case.stop)
        self.assertEqual(case.c.semantic_result['outcome'], 'VERIFIED')

    def test_cold_tick_deadline_and_close_reserve(self):
        case = self.start(27)
        self.wait_and_renew(case)
        memo = self.guards.head.__self__
        memo.slots.clear()
        self.calls.clear()
        case.supervisor.ingress_before_wait(case.scheduled, case.stop)
        sample = case.c.semantic_result
        self.assertEqual(sample['outcome'], 'CLOSED')
        self.assertEqual(self.calls.count('pkeyutl'), 26)
        self.assertTrue(700 <= sample['durationMs'] <= 900)
        self.assertFalse(any(self.tables.members.values()))
        print('forced cold tick ms', sample['durationMs'], flush=True)
        self.wait_and_renew(case)
        self.calls.clear()
        case.supervisor.ingress_before_wait(case.scheduled, case.stop)
        self.assertEqual(case.c.semantic_result['outcome'], 'VERIFIED')
        self.assertEqual(self.calls, [])
        self.wait_and_renew(case)
        command = case.sup.semantic_command
        def broken(*args, deadline):
            if deadline is not None:
                raise OSError()
            return command(*args, deadline=deadline)
        case.sup.semantic_command = broken
        row = case.supervisor.ingress_before_wait(case.scheduled, case.stop)
        self.assertFalse(case.locked)
        self.assertEqual((row['state'], row['reason']), ('BLOCKED', 'R3_SEMANTIC_CLOSE_UNVERIFIED'))
        self.assertEqual(row['lastSemanticTick']['outcome'], row['reason'])

    def test_memo_capacity_pruning_and_rejected_signature(self):
        self.start(27)
        guards, chain = self.guards, self.chain
        memo = guards.head.__self__
        a = guards.head.__func__.__globals__
        m = guards.mandates
        self.assertEqual(len(memo.slots), 26)
        for suffix in ('json', 'signature.json'):
            (chain.directory / f'26.{suffix}').unlink()
        def head():
            return memo.head(m, chain.anchor, str(chain.ledger), chain.ssl, str(chain.directory),
                             *[chain.scope[k] for k in ('installationRef', 'entityRef', 'issuerRef')], lambda: chain.now)
        self.calls.clear()
        self.assertEqual(head()['sequence'], 25)
        self.assertEqual(len(memo.slots), 25)
        self.assertEqual(self.calls, [])
        auth = m.MandateAuthenticator(chain.anchor, str(chain.ledger), chain.ssl, lambda: chain.now)
        # Exercise the actual slot cap without signing 230 further payloads.
        with self.assertRaisesRegex(a['OperationDenied'], 'OPERATION_CHAIN_UNBOUNDED'):
            memo.verify(m, auth, a['MAX_CHAIN'] + 1, b'', b'', b'')
        path = chain.directory / '1.signature.json'
        signature = json.loads(path.read_bytes())
        signature['signature'] = '00' * 64
        path.write_bytes(C.canonical(signature))
        for attempt in (1, 2):
            with self.assertRaisesRegex(a['OperationDenied'], 'OPERATION_SIGNATURE_INVALID'):
                head()
            self.assertEqual(memo.slots, {})
            self.assertEqual(self.calls.count('pkeyutl'), attempt)

    def test_authority_between_lease_and_open(self):
        for change in ('STOP', 'OPERATE', 'revoked', 'signature', 'epoch', 'replace'):
            with self.subTest(change=change), ExitStack() as cleanup:
                case = self.start(27)
                cleanup.callback(self.doCleanups)
                self.wait_and_renew(case)
                if change in ('revoked', 'epoch'):
                    case.supervisor.ingress_before_wait(case.scheduled, case.stop)
                    self.assertTrue(all(self.tables.members.values()))
                    self.wait_and_renew(case)
                chain = self.chain
                memo = self.guards.head.__self__
                if change in ('STOP', 'OPERATE'):
                    chain.append(change)
                elif change == 'revoked':
                    chain.revoke()
                elif change == 'epoch':
                    next(iter(self.rows.values()))['epoch'] += 1
                elif change == 'signature':
                    path = chain.directory / '26.signature.json'
                    signature = json.loads(path.read_bytes())
                    signature['signature'] = '00' * 64
                    path.write_bytes(C.canonical(signature))
                else:
                    # Replace an already read file with identical content while a
                    # later (valid, newly issued) signature is being verified.
                    chain.append()
                    target = chain.directory / '1.json'
                    verify = self.guards.mandates.MandateAuthenticator.verify
                    def replace(auth, *args):
                        other = chain.root / 'replacement'
                        other.write_bytes(target.read_bytes())
                        other.replace(target)
                        return verify(auth, *args)
                    cleanup.enter_context(patch.object(self.guards.mandates.MandateAuthenticator, 'verify', replace))
                start = case.clock()
                row = case.supervisor.ingress_before_wait(case.scheduled, case.stop)
                self.assertEqual(row['state'], 'BLOCKED')
                if change == 'replace':
                    self.assertEqual(self.guards.reason, 'OPERATION_CHAIN_CHANGED_DURING_VERIFICATION')
                if change == 'signature':
                    self.assertFalse(memo.slots)
                self.assertLessEqual(case.clock() - start, .95)
                self.assertFalse(any(self.tables.members.values()))
                self.assertIsNone(case.c.semantic_epoch())
                self.assertFalse(case.locked)

    def test_revocation_during_enable_is_closed_before_acknowledgement(self):
        case = self.start(27)
        self.wait_and_renew(case)
        command = self.tables.command
        def revoke_on_enable(argv, table, raw):
            result = command(argv, table, raw)
            if raw and b'add element inet' in raw:
                self.chain.revoke()
            return result
        with patch.object(self.tables, 'command', revoke_on_enable):
            row = case.supervisor.ingress_before_wait(case.scheduled, case.stop)
        self.assertEqual((row['state'], self.guards.reason), ('BLOCKED', 'OPERATION_KEY_REVOKED'))
        self.assertTrue(any(all(batch.values()) for batch in self.tables.batches))
        self.assertFalse(any(self.tables.members.values()))
        self.assertIsNone(case.c.semantic_epoch())
        self.assertEqual(row['lastSemanticTick']['outcome'], 'CLOSED')
        self.assertLessEqual(row['lastSemanticTick']['durationMs'], 900)


@unittest.skipUnless(os.environ.get('OUF_R3_V27_NATIVE') == '1', 'requires explicit native opt-in')
class Native(unittest.TestCase):
    def test_warm_open_and_audit(self):
        self.assertEqual(sys.platform, 'linux')
        self.assertEqual((os.getuid(), os.getgid()), (0, 0))
        v25.live.semantic_kernel()
        subprocess.run(['unshare', '--mount', '--net', '--propagation', 'private', sys.executable,
                        '-I', '-B', str(Path(__file__).resolve()), '--native'], check=True, timeout=120)


def native_worker():
    """Use the v25 private veth/nft traffic proof with the emitted v27 guard."""
    _, result = fixture(27)
    prefix = 'versions/27/source/'
    auth = C.contract_module(result['documents'][prefix + overlay.AUTH], 'native_authorization')
    sup = C.contract_module(result['documents'][prefix + C.SUPERVISOR], 'native_supervisor')
    sup.__dict__['__builtins__']['__import__'] = builtins.__import__
    sup.Path = auth.Path = Path
    with tempfile.TemporaryDirectory(dir='/var/lib', prefix='ouf-v27-test-') as directory:
        chain = Chain(Path(directory))
        with patch.dict(os.environ, OUF_R3_V13_NATIVE='1'):
            def bind(cfg, coordinator, fixture_guards, read, **kwargs):
                nft_binding = cfg['coordinator']['nftBinding']
                cfg = chain.configure(C.document(result['documents']['versions/27/supervisor/configuration.json']))
                cfg['coordinator']['nftBinding'] = nft_binding
                cfg['registryRoot'] = str(chain.root / 'registry')
                # The native v25 fixture supplies the real port and its table
                # footprint, and a synthetic southbound driver and epoch.
                registry = Path(cfg['registryRoot'])
                registry.mkdir(mode=0o700, exist_ok=True)
                rows = {}
                for role in chain.payload['roles'].values():
                    cid = role['containerId']
                    base = registry / cid
                    base.mkdir(mode=0o700, exist_ok=True)
                    chain.write(base / 'operation.lock', b'')
                    rows[cid] = dict(epoch=9, state='STARTED', generation=dict(pid=7),
                                     authorizationSha256=chain.digest, driverHash='f' * 64)
                memo = auth.SignatureMemo()
                guards = sup.Guards(SimpleNamespace(value=cfg), mandates, chain.payload['lease']['leaseStructureHash'],
                                    RuntimeError, head=memo.head, current=lambda root, cid: rows[cid],
                                    boot=lambda: 'fixture', live=lambda *_: True, clock=lambda: chain.now)
                t0 = time.monotonic()
                guards.fixed = guards.scope_guard()
                assert len(memo.slots) == 26
                print(f'cold authority {time.monotonic()-t0:.4f}s', flush=True)
                # TickFixture binds its native gate via this constructor.
                with patch.object(sup, 'SemanticGate', v25.live.SemanticGate):
                    sup.bind_semantic_gate(cfg, coordinator, guards, read, **kwargs)
                tick = coordinator.semantic_tick
                def measured(*args):
                    t0 = time.monotonic()
                    with patch.object(mandates.MandateAuthenticator, 'verify',
                                      side_effect=AssertionError('unexpected cold signature')):
                        tick(*args)
                    elapsed = time.monotonic() - t0
                    if coordinator.semantic_result['outcome'] == 'VERIFIED':
                        assert elapsed < cfg['leaseRenewal']['semanticTickBudgetSeconds']
                        print(f'warm v27 verified tick {elapsed:.4f}s', flush=True)
                coordinator.semantic_tick = measured
            with patch.object(v25.live, 'bind_semantic_gate', bind):
                v25.native_reconcile()


if __name__ == '__main__':
    if sys.argv[1:] == ['--native'] and os.environ.get('OUF_R3_V27_NATIVE') == '1':
        native_worker()
    else:
        unittest.main()
