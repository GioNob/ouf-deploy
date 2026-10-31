"""Real journal/lifecycle; simulated Engine, profile, authority and gateway.

This verifies prefix dispatch and witness refusal boundaries. It does not
qualify real OCI, target IAM, a full factory or a JVM recovery.
"""
import copy
from contextlib import contextmanager
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_lifecycle as fixture
from tools.semantic_registry_recovery_execution import authorization as a, bootstrap as b, core as c, lifecycle as l


class Profile:
    def __init__(self, request):
        self.request = copy.deepcopy(request)
    def verify(self, request):
        c.require(request == self.request, 'FIXTURE_PROFILE_DRIFT')
        return c.digest(request)


class Gateway:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle
        self.calls = []
    def guard(self):
        self.lifecycle.journal()
    def verify(self, *, endpoint_required):
        self.calls.append(endpoint_required)
        actual = self.lifecycle.inspect()
        c.require(actual['State']['Running'] is endpoint_required, 'FIXTURE_GATEWAY_ENDPOINT_DRIFT')
        return {'fixtureRouteBindingVerified': True, 'endpointRequired': endpoint_required}


class Bootstrap(unittest.TestCase):
    post_calls = fixture.Tests.post_calls

    def setUp(self):
        original = Path.read_text
        def fixture_boot(path, *args, **kwargs):
            if str(path) == '/proc/sys/kernel/random/boot_id':
                return 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n'
            return original(path, *args, **kwargs)
        handle = patch.object(Path, 'read_text', fixture_boot)
        handle.start(); self.addCleanup(handle.stop)
        spec = importlib.util.spec_from_file_location('bootstrap_candidate', fixture.ROOT.parent / 'semantic_registry_recovery_composition/compose.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.request = {'Image': 'sha256:' + 'b'*64}
        self.baseline = {'Id': 'a'*64, 'Image': self.request['Image'], 'Config': {'fixture': 'PRIVATE'},
            'HostConfig': {'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0}, 'OomKillDisable': False},
            'Mounts': [], 'NetworkSettings': {}, 'RestartCount': 0,
            'State': {'Status': 'exited', 'Running': False, 'Pid': 0, 'StartedAt': 'old',
                'Paused': False, 'Restarting': False, 'Dead': False}}
        pin = {'containerId': 'a'*64, 'imageId': self.request['Image'], 'configHash': c.digest(self.baseline['Config']),
            'hostConfigHash': c.digest(self.baseline['HostConfig']), 'mountsHash': c.digest([])}
        self.proposal = {'registry': pin, 'requiredGates': list(module.GATES), 'unresolvedGateCount': 8}
        self.plan = module.candidate_contract(self.proposal, 'b'*64, 'c'*64)
        self.wall, self.mono = time.time(), time.monotonic()
        self.new = {'containerId': 'a'*64, 'bootId': b.current_boot(), 'pid': 4242,
            'startTicks': 12345, 'namespaceDevice': 4, 'namespaceInode': 12}
        temporary = tempfile.TemporaryDirectory(dir=Path.cwd()); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / ('semantic-registry-recovery-' + self.plan['logicalOperationRef'])
        root.mkdir(mode=0o700); self.store = c.Store(root, self.plan['logicalOperationRef'])
        self.auth = fixture.FixtureAuthority(self.request)
        self.raw = c.encoded({'semanticRegistryRecovery': a.scope(self.plan), 'issuedAt': self.wall - 1, 'expiresAt': self.wall + 801})
        handle = patch.object(a, 'cutover_type', return_value=fixture.FixtureAuthority)
        handle.start(); self.addCleanup(handle.stop)
        self.authority = a.AuthorityScope(self.auth, self.raw, self.plan, self.request)
        self.store.initialize(c.initial(self.plan, authority_hash=self.authority.hash, expires_unix=self.wall + 800,
            expires_monotonic=self.mono + 800, boot_id=self.new['bootId'], predecessor_history_hash='e'*64,
            created_unix=self.wall, created_monotonic=self.mono))
        self.server = SimpleNamespace(actual=copy.deepcopy(self.baseline), kind='GATE_WAITING', calls=[])
        self.engine = fixture.Engine.__new__(fixture.Engine)
        def engine_request(method, path, *args):
            self.server.calls.append((method, path)); state = self.server.actual['State']
            if method == 'GET': return 200, copy.deepcopy(self.server.actual)
            suffix = path.rsplit('/', 1)[-1]
            if suffix == 'start': state.update(Status='running', Running=True, Pid=4242, StartedAt='new', Paused=False)
            elif suffix == 'pause': state.update(Status='paused', Paused=True)
            elif suffix == 'unpause': state.update(Status='running', Paused=False)
            elif suffix == 'kill?signal=SIGUSR1': self.server.kind = 'APPLICATION_RUNNING'
            else: raise AssertionError('Unexpected fixture effect')
            return 204, None
        self.engine.request = engine_request
        for name, value in (('process_type', lambda: fixture.FixtureProcess),
                ('observe_generation', lambda *_: (copy.deepcopy(self.new), {'processKind': self.server.kind}))):
            handle = patch.object(l, name, value); handle.start(); self.addCleanup(handle.stop)
        self.native = l.Lifecycle(self.engine, self.authority, self.store, self.plan, self.request, self.baseline, self.proposal)

    def prepare(self):
        for name, result in (('profile_type', Profile), ('gateway_type', Gateway)):
            handle = patch.object(b, name, return_value=result)
            handle.start(); self.addCleanup(handle.stop)
        self.profile = Profile(self.request); self.auth.execution_profile = self.profile
        scope = b.bootstrap_scope(self.plan, self.request, self.profile, self.new['bootId'])
        raw = json.loads(self.raw); raw[b.KEY] = scope; self.raw = c.encoded(raw)
        self.authority = a.AuthorityScope(self.auth, self.raw, self.plan, self.request)
        row = self.store.read()
        self.store.cas(row, {**row, 'authorityHash': self.authority.hash, 'version': row['version'] + 1})
        self.native.authority = self.authority
        original = self.native.engine.request
        def request(method, path, *args, **kwargs):
            if path == '/v1.44/images/' + self.request['Image'] + '/json':
                c.require(method == 'GET', 'FIXTURE_IMAGE_READ_ONLY')
                return 200, {'Id': self.request['Image']}
            return original(method, path, *args, **kwargs)
        self.native.engine.request = request
        self.gateway = Gateway(self.native)
        self.ports = b.BootstrapPorts(self.native, self.profile, self.gateway)
        self.runner = c.Runner(self.plan, self.store, self.ports, boot_id=self.new['bootId'])
        return self.ports.witness

    def prefix(self):
        witness = self.prepare()
        for _ in range(4):
            self.runner.step()
        return witness

    def claim(self):
        row = self.store.read(); stage = self.plan['stages'][row['nextStage']]
        effects = copy.deepcopy(row['effects'])
        effects.append({'stage': stage['name'], 'intentHash': stage['intentHash'],
                        'authorityHash': self.authority.hash, 'state': 'CLAIMED', 'nativeEvidence': None})
        self.store.cas(row, {**row, 'effects': effects, 'state': 'IN_FLIGHT', 'version': row['version'] + 1})
        return stage

    def complete(self, proof):
        row = self.store.read(); effects = copy.deepcopy(row['effects'])
        effects[-1].update(state='APPLIED', nativeEvidence=proof, nativeEvidenceHash=c.digest(proof))
        cursor = row['nextStage'] + 1
        self.store.cas(row, {**row, 'effects': effects, 'nextStage': cursor,
            'state': 'COMPLETED' if cursor == 12 else 'READY', 'version': row['version'] + 1})

    def before_release(self):
        witness = self.prefix()
        # Explicit synthetic downstream admission evidence for witness-only
        # tests. This does not execute or qualify the production node owner.
        for _ in range(3):
            self.claim(); self.complete({'newGeneration': self.new, 'syntheticDownstreamAdmission': True})
        stage = self.claim(); self.native.apply(stage)
        state, proof = self.native.observe(stage); self.assertEqual(state, 'APPLIED'); self.complete(proof)
        self.claim(); self.complete(self.native.process_evidence(self.native.inspect()))
        self.claim()
        return witness

    def test_prefix_only_starts_and_pauses_same_gate_then_stops_before_stage_four(self):
        witness = self.prefix(); row = self.store.read(); proof = witness.observe()
        self.assertEqual(row['nextStage'], 4)
        self.assertEqual(self.post_calls(), ['/v1.44/containers/' + 'a'*64 + '/start',
                                           '/v1.44/containers/' + 'a'*64 + '/pause'])
        self.assertEqual(proof['runtimeGeneration'], self.new)
        self.assertEqual(proof['processKind'], 'GATE_WAITING'); self.assertTrue(proof['paused'])
        self.assertIsNone(proof['durableReleaseAttemptHash'])
        with self.assertRaisesRegex(c.RecoveryDenied, 'STOP_BEFORE_ADMISSION'):
            self.runner.step()
        self.assertEqual(self.store.read(), row)

    def test_pregrant_never_accepts_unpaused_gate_or_jvm_before_release(self):
        witness = self.prefix(); actual = copy.deepcopy(self.server.actual)
        for drift in ('unpaused', 'java'):
            self.server.actual = copy.deepcopy(actual); self.server.kind = 'GATE_WAITING'
            if drift == 'unpaused': self.server.actual['State'].update(Paused=False, Status='running')
            else: self.server.kind = 'APPLICATION_RUNNING'
            with self.assertRaisesRegex(c.RecoveryDenied, 'SAME_FENCED'):
                witness.observe()

    def test_pregrant_before_durable_pause_is_refused(self):
        witness = self.prepare(); self.runner.step(); self.runner.step()
        with self.assertRaisesRegex(c.RecoveryDenied, 'DURABLE_POSTBOOT_PAUSE_PREFIX'):
            witness.observe()

    def test_start_ack_and_first_capture_allow_running_gate_before_core_publishes_generation(self):
        self.prepare(); self.runner.step()
        stage = self.claim(); self.native.apply(stage)
        pending = self.store.read()
        self.assertEqual(pending['nextStage'], 1); self.assertIsNone(pending['newGeneration'])
        self.assertTrue(pending['effects'][1]['nativeResponse204'])
        self.gateway.calls.clear()
        row = self.runner.step()
        # Pending START is reconciled by Lifecycle using its durable capture;
        # Gateway endpoint verification resumes at the following checkpoint.
        self.assertEqual(self.gateway.calls, [])
        self.assertEqual(row['nextStage'], 2); self.assertEqual(row['newGeneration'], self.new)
        self.assertEqual(len(self.post_calls()), 1)

    def test_running_pid_after_start_cannot_replace_the_first_durable_capture(self):
        self.prepare(); self.runner.step()
        stage = self.claim(); self.native.apply(stage)
        pending = self.store.read(); self.new['startTicks'] += 1
        self.gateway.calls.clear()
        with self.assertRaisesRegex(c.RecoveryDenied, 'FIRST_DURABLY_CAPTURED_REGISTRY_GENERATION_CHANGED'):
            self.runner.step()
        self.assertEqual(self.gateway.calls, [])
        self.assertIsNone(self.store.read()['newGeneration'])
        self.assertEqual(self.store.read()['effects'][1]['nativeFirstProcess'],
                         pending['effects'][1]['nativeFirstProcess'])
        self.assertEqual(len(self.post_calls()), 1)

    def test_changed_pid_ticks_or_namespace_never_becomes_current_owner_generation(self):
        witness = self.prefix(); saved = copy.deepcopy(self.new)
        for field in ('pid', 'startTicks', 'namespaceDevice', 'namespaceInode'):
            self.new.update(saved); self.new[field] += 1
            with self.assertRaisesRegex(c.RecoveryDenied, 'SAME_FENCED'):
                witness.observe()

    def test_start_capture_gap_is_observation_only_no_second_start(self):
        self.prepare(); self.runner.step()
        with patch.object(self.native, 'process_evidence', side_effect=OSError('fixture capture gap')):
            with self.assertRaises(OSError): self.runner.step()
        row = self.runner.step()
        self.assertEqual(row['nextStage'], 1); self.assertEqual(len(self.post_calls()), 1)
        self.assertIsNone(row['newGeneration'])

    def test_revocation_blocks_pause_and_preserves_first_claim(self):
        self.prepare(); self.runner.step(); self.runner.step(); self.runner.step()
        before = self.store.read(); self.auth.current = False
        with self.assertRaisesRegex(c.RecoveryDenied, 'CURRENT_DUAL_ROLE'):
            self.runner.step()
        self.assertEqual(self.store.read(), before); self.assertEqual(len(self.post_calls()), 1)

    def test_changed_boot_or_bootstrap_signature_scope_is_refused(self):
        witness = self.prefix()
        with patch.object(b, 'current_boot', return_value='11111111-2222-3333-4444-555555555555'):
            with self.assertRaisesRegex(c.RecoveryDenied, 'CURRENT_SIGNED_POSTBOOT'):
                witness.observe()
        witness.scope['javaReleaseAllowed'] = True
        with self.assertRaisesRegex(c.RecoveryDenied, 'CURRENT_SIGNED_POSTBOOT'):
            witness.observe()

    def test_jvm_without_durable_release_attempt_is_refused(self):
        witness = self.before_release(); self.server.kind = 'APPLICATION_RUNNING'
        with self.assertRaisesRegex(c.RecoveryDenied, 'SAME_FENCED'):
            witness.observe(stage='ACTIVE')

    def test_lost_release_ack_allows_same_generation_observation_but_never_replay(self):
        witness = self.before_release(); stage = self.plan['stages'][9]
        original = self.native.engine.request
        def lost_ack(method, path, *args, **kwargs):
            value = original(method, path, *args, **kwargs)
            if method == 'POST' and path.endswith('/kill?signal=SIGUSR1'):
                raise OSError('fixture lost ack after accepted signal')
            return value
        self.native.engine.request = lost_ack
        with self.assertRaises(OSError): self.native.apply(stage)
        proof = witness.observe(stage='ACTIVE')
        self.assertEqual(proof['processKind'], 'APPLICATION_RUNNING')
        self.assertIsNotNone(proof['durableReleaseAttemptHash'])
        self.assertIsNone(proof['durableReleaseEvidenceHash'])
        with self.assertRaisesRegex(c.RecoveryDenied, 'ALREADY_ATTEMPTED'):
            self.native.apply(stage)
        self.assertEqual(len(self.post_calls()), 4)

    def test_completed_release_and_final_checkpoint_keep_same_generation(self):
        witness = self.before_release(); stage = self.plan['stages'][9]
        self.native.apply(stage); state, proof = self.native.observe(stage)
        self.assertEqual(state, 'APPLIED'); self.complete(proof)
        for _ in range(2):
            observed = witness.observe(stage='ACTIVE')
            self.assertIsNotNone(observed['durableReleaseEvidenceHash'])
            self.claim(); self.complete({'newGeneration': self.new, 'syntheticReadinessOnly': True})
        self.assertEqual(witness.observe(stage='ACTIVE')['checkpoint'], 12)
        with self.assertRaisesRegex(c.RecoveryDenied, 'CHECKPOINT_FOUR'):
            witness.observe()

    def test_bootstrap_refuses_unpause_even_with_signed_later_native_stage(self):
        self.prefix(); row = self.store.read()
        with self.assertRaisesRegex(c.RecoveryDenied, 'STOP_BEFORE_ADMISSION'):
            self.ports.apply(self.plan, row, self.plan['stages'][7])
        self.assertEqual(len(self.post_calls()), 2)

    def installer_fixture(self):
        self.prepare()
        parent = self.store.root.parent / 'unused-installation-parent'; parent.mkdir(mode=0o700)
        root = parent / self.store.root.name
        context = {'plan': self.plan, 'executionRoot': str(root)}
        factory = ModuleType('tools.semantic_registry_recovery_execution.factory')
        factory.factory_scope = lambda value: {'executionRoot': value['executionRoot'], 'syntheticContextHash': c.digest(value)}
        producer = ModuleType('tools.semantic_policy_token_owner.producer')
        @contextmanager
        def protected_directory(path):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: yield fd
            finally: os.close(fd)
        producer.protected_directory = protected_directory
        handle = patch.dict(sys.modules, {factory.__name__: factory, producer.__name__: producer})
        handle.start(); self.addCleanup(handle.stop)
        self.auth.expected['predecessorHistoryHash'] = 'e'*64
        raw = json.loads(self.raw)
        raw['semanticRegistryPostbootInstallation'] = b.installation_scope(context, self.request, self.profile, self.new['bootId'])
        raw['semanticRegistryRecoveryReads'] = b.read_scope(self.plan, root)
        raw = c.encoded(raw)
        scoped = a.AuthorityScope(self.auth, raw, self.plan, self.request)
        factory.current_scope = lambda *_: (factory.factory_scope(context),
            {'registryInputs': {'creationRequest': self.request}}, scoped)
        # Only filesystem initialization is tested here. Current factory and
        # parent-custody authentication are explicit fixture substitutions.
        return context, raw, root

    def test_bootstrap_installer_creates_once_without_token_owner_or_runtime(self):
        context, raw, root = self.installer_fixture()
        receipt = b.install(context, self.auth, raw)
        store = c.Store(root, self.plan['logicalOperationRef'])
        journal, reads = (root/'recovery.json').read_bytes(), (root/'native-reads.json').read_bytes()
        self.assertEqual(store.read()['nextStage'], 0)
        self.assertEqual(receipt['tokenGrantAttempts'], 0); self.assertEqual(receipt['runtimeEffectsDispatched'], 0)
        self.assertEqual(self.post_calls(), [])
        with self.assertRaises(FileExistsError): b.install(context, self.auth, raw)
        self.assertEqual((root/'recovery.json').read_bytes(), journal)
        self.assertEqual((root/'native-reads.json').read_bytes(), reads)

    def test_bootstrap_installer_partial_directory_and_claims_remain_consumed(self):
        context, raw, root = self.installer_fixture()
        with patch.object(b.ReadBudget, 'initialize', side_effect=OSError('fixture interrupted installation')):
            with self.assertRaises(OSError): b.install(context, self.auth, raw)
        before = (root/'recovery.json').read_bytes()
        with self.assertRaises(FileExistsError): b.install(context, self.auth, raw)
        self.assertEqual((root/'recovery.json').read_bytes(), before)
        self.assertFalse((root/'native-reads.json').exists())
        self.assertFalse((root/'bootstrap-installation.json').exists())

    def test_missing_bootstrap_installation_scope_creates_nothing(self):
        context, raw, root = self.installer_fixture()
        bad = json.loads(raw); bad.pop('semanticRegistryPostbootInstallation')
        with self.assertRaisesRegex(c.RecoveryDenied, 'SIGNED_POSTBOOT_INSTALLATION'):
            b.install(context, self.auth, c.encoded(bad))
        self.assertFalse(root.exists())


if __name__ == '__main__':
    unittest.main()
