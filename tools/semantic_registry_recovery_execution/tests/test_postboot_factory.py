"""Read-only resumption wiring with explicit native collaborator substitutes.

Production factory/dispatch/NativePorts function bodies and the real Core
Runner/Store are exercised. Synthetic signatures, witness, node, DB, Gateway
and owner state are declared fixtures, never native qualification or authority.
"""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from tools.semantic_registry_recovery_execution import core as c
from tools.semantic_registry_recovery_composition.compose import candidate_contract, GATES
from tools.semantic_registry_recovery_execution.tests.test_postboot_scopes import load_parts

SOURCE = Path(__file__).resolve().parents[1]


class FixtureAuthority:
    def __init__(self):
        self.active = True
        self.calls = []

    def __call__(self, raw):
        self.calls.append(raw)
        return self.active


class FixtureLifecycle:
    pass


class FixtureBootstrapPorts(c.Ports):
    def guard(self, *args):
        raise AssertionError('Factory must not advance a stage')

    def apply(self, *args):
        raise AssertionError('Factory must not dispatch a runtime effect')

    def observe(self, *args):
        raise AssertionError('Factory must use only its current gate witness')


class FixturePostbootOwner:
    pass


class FixtureLegacyOwner:
    pass


class PostbootFactory(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=SOURCE.parents[1]); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        proposal = {'registry': {'containerId': 'a'*64}, 'requiredGates': list(GATES), 'unresolvedGateCount': 8}
        self.plan = candidate_contract(proposal, 'b'*64, 'c'*64)
        path = self.root/('semantic-registry-recovery-'+self.plan['logicalOperationRef']); path.mkdir(mode=0o700)
        self.store = c.Store(path, self.plan['logicalOperationRef'])
        self.row = {'nextStage': 4, 'version': 7, 'state': 'READY'}
        self.calls = []
        self.authority = FixtureAuthority(); self.raw = b'DISPOSABLE_SIGNED_SCOPE_FIXTURE'
        self.scope = SimpleNamespace(hash='d'*64, authority=self.authority, raw=self.raw)
        self.profile, self.verifier, self.signer = object(), object(), object()
        self.life = FixtureLifecycle()
        self.life.plan, self.life.store, self.life.authority = self.plan, self.store, self.scope
        self.life.engine = SimpleNamespace(path='/fixture/docker.sock', binding=(1,2,0,0,384))
        self.life.journal = lambda: copy.deepcopy(self.row)
        self.native = {'plan': self.plan, 'executionRoot': str(path),
            'engineBinding': {'socketPath': self.life.engine.path, 'socketBinding': list(self.life.engine.binding)},
            'nodeRecipe': {'renewableToken': {'minimumRemainingSeconds': 90}},
            'database': {'readiness': {'fixture': 'readiness'}, 'postgres': {'fixture': 'pg'}, 'program': {'fixture': 'program'}},
            'originalRequest': {'fixture': 'frozenOriginalRequest'}}
        self.retained = {'registryInputs': {'readinessScope': copy.deepcopy(self.native['database']['readiness']),
                                           'imageAudit': {'fixture': 'imageAudit'}}}
        self.owner_context = {'fixture': 'currentOwnerContext'}
        self.owner = FixturePostbootOwner(); self.owner.observer = True
        self.owner.lease = lambda minimum: self.calls.append(('lease', minimum))
        self.prefix = FixtureBootstrapPorts(); self.prefix.lifecycle, self.prefix.profile = self.life, self.profile
        self.prefix.witness = SimpleNamespace(lifecycle=self.life, observe=lambda **kw: self.calls.append(('witness', kw)))
        self.owner.gate_witness = self.prefix.witness
        self.prefix.gateway = SimpleNamespace(lifecycle=self.life, budget=object())
        self.boot = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        self.runner = c.Runner(self.plan, self.store, self.prefix, boot_id=self.boot)
        dispatch = dict(require=c.require, InstalledTokenOwner=FixtureLegacyOwner, PostbootTokenOwner=FixturePostbootOwner,
                        retained_lease=lambda *args: self.fail('Historical owner must not be selected'))
        load_parts(SOURCE/'token_observer.py', {'require_observer', 'guard_lease'}, dispatch)
        self.require_observer, guard_lease = dispatch['require_observer'], dispatch['guard_lease']
        test = self

        class Node:
            def __init__(inner, lifecycle, profile, owner, verifier, signer, recipe):
                test.require_observer(owner, lifecycle)
                test.calls.append(('node', lifecycle, profile, owner, verifier, signer, recipe))
                inner.lifecycle, inner.token_owner = lifecycle, owner

        class Database:
            def __init__(inner, lifecycle, readiness, postgres, program, audit, budget):
                test.calls.append(('database', lifecycle, readiness, postgres, program, audit, budget))
                inner.lifecycle = lifecycle
                if test.mutate_during_database:
                    test.row['version'] += 1

        class Admission:
            def __init__(inner, database, node):
                c.require(database.lifecycle is node.lifecycle, 'FIXTURE_DIFFERENT_ADMISSION_LIFECYCLE')
                test.calls.append(('admission', database, node)); inner.lifecycle = node.lifecycle

        class Gateway:
            pass

        self.prefix.gateway = Gateway(); self.prefix.gateway.lifecycle = self.life; self.prefix.gateway.budget = object()

        class Semantic:
            def __init__(inner, gateway, profile):
                test.calls.append(('semantic', gateway, profile)); inner.lifecycle, inner.gateway = gateway.lifecycle, gateway

        ports = dict(Ports=c.Ports, require=c.require, digest=c.digest, Lifecycle=FixtureLifecycle,
                     CurrentAdmission=Admission, CurrentGateway=Gateway, OriginalSemanticRequest=Semantic)
        load_parts(SOURCE/'native.py', {'NativePorts'}, ports)
        self.mutate_during_database = False

        def current_scope(context, authority, raw):
            self.assertIs(context, self.native); self.assertIs(authority, self.authority); self.assertEqual(raw, self.raw)
            self.calls.append(('scope',)); return {}, self.retained, self.checked_scope

        def build_observer(context, authority, raw, witness):
            self.assertIs(context, self.owner_context); self.assertIs(authority, self.authority)
            self.assertEqual(raw, self.raw); self.assertIs(witness, self.prefix.witness)
            self.calls.append(('observer', witness)); return self.owner

        self.checked_scope = self.scope
        env = dict(require=c.require, digest=c.digest, Runner=c.Runner, BootstrapPorts=FixtureBootstrapPorts,
                   current_scope=current_scope, build_observer=build_observer, guard_lease=guard_lease,
                   RecoveryNodeOwner=Node, CurrentDatabase=Database, CurrentAdmission=Admission,
                   OriginalSemanticRequest=Semantic, NativePorts=ports['NativePorts'])
        load_parts(SOURCE/'postboot_factory.py', {'build_on_bootstrap'}, env)
        self.build = env['build_on_bootstrap']

    def resume(self, runner=None, **kw):
        return self.build(self.runner if runner is None else runner, self.native, self.owner_context,
            kw.get('authority', self.authority), kw.get('raw', self.raw), self.verifier, self.signer)

    def test_resume_reuses_exact_lifecycle_store_gateway_budget_profile_and_observer(self):
        before = copy.deepcopy(self.row); files = list(self.store.root.iterdir())
        resumed = self.resume()
        self.assertIs(type(resumed), c.Runner); self.assertIs(resumed.store, self.store)
        self.assertIs(resumed.ports.lifecycle, self.life); self.assertIs(resumed.ports.gateway, self.prefix.gateway)
        self.assertEqual(resumed.boot_id, self.boot); self.assertEqual(resumed.plan_hash, self.runner.plan_hash)
        self.assertEqual([x[0] for x in self.calls], ['scope','witness','observer','lease','node','database','admission','semantic'])
        node = self.calls[4]; database = self.calls[5]
        self.assertEqual(node[1:], (self.life, self.profile, self.owner, self.verifier, self.signer, self.native['nodeRecipe']))
        self.assertIs(database[-1], self.prefix.gateway.budget)
        self.assertIs(database[-2], self.retained['registryInputs']['imageAudit'])
        self.assertEqual(self.calls[1], ('witness', {'stage': 'ACTIVE'}))
        self.assertEqual(self.calls[3], ('lease', 90))
        self.assertEqual(self.row, before); self.assertEqual(list(self.store.root.iterdir()), files)
        self.assertEqual(self.authority.calls, [self.raw])

    def test_passed_boolean_callback_or_namespace_is_not_an_existing_runner(self):
        for fake in (True, lambda: True, SimpleNamespace(ports=self.prefix, store=self.store)):
            with self.subTest(fake=type(fake)), self.assertRaisesRegex(c.RecoveryDenied, 'ACTUAL_EXISTING_BOOTSTRAP_RUNNER'):
                self.resume(runner=fake)
        self.assertEqual(self.calls, [])

    def test_an_unrelated_or_uncompleted_prefix_is_refused_before_owner_construction(self):
        for stage in (0,3,13):
            self.row['nextStage'] = stage
            with self.subTest(stage=stage), self.assertRaisesRegex(c.RecoveryDenied, 'SAME_PAUSED_POSTBOOT_STORE'):
                self.resume()
        self.row['nextStage'] = 4
        self.life.store = object()
        with self.assertRaisesRegex(c.RecoveryDenied, 'SAME_PAUSED_POSTBOOT_STORE'):
            self.resume()
        self.assertEqual(self.calls, [])

    def test_different_authority_or_raw_cannot_substitute(self):
        for inputs in ({'authority': FixtureAuthority()}, {'raw': b'DIFFERENT_SCOPE'}):
            with self.subTest(inputs=inputs), self.assertRaisesRegex(c.RecoveryDenied, 'SAME_PAUSED_POSTBOOT_STORE'):
                self.resume(**inputs)
        self.assertEqual(self.calls, [])

    def test_scope_engine_or_root_mismatch_stops_before_native_composition(self):
        for field in ('scope','engine','root'):
            original_scope = self.checked_scope; original = copy.deepcopy(self.native)
            if field == 'scope': self.checked_scope = SimpleNamespace(hash='f'*64)
            elif field == 'engine': self.native['engineBinding']['socketPath'] = '/fixture/other.sock'
            else: self.native['executionRoot'] += '-copy'
            with self.subTest(field=field), self.assertRaisesRegex(c.RecoveryDenied, 'SAME_CURRENT_POSTBOOT_NATIVE_CONTEXT'):
                self.resume()
            self.assertEqual(self.calls[-1], ('scope',))
            self.checked_scope = original_scope; self.native.clear(); self.native.update(original)
        self.assertTrue(all(item == ('scope',) for item in self.calls))

    def test_writer_or_fake_observer_never_reaches_node_admission(self):
        for owner in (SimpleNamespace(observer=True, lease=lambda _: True), FixturePostbootOwner()):
            owner.observer = False if type(owner) is FixturePostbootOwner else True
            self.owner = owner
            with self.subTest(owner=type(owner)), self.assertRaisesRegex(c.RecoveryDenied, 'ACTUAL_CURRENT_BOOT_TOKEN_OWNER_OBSERVER'):
                self.resume()
        self.assertNotIn('node', [item[0] for item in self.calls])

    def test_observer_for_another_lifecycle_is_refused(self):
        self.owner.gate_witness = SimpleNamespace(lifecycle=FixtureLifecycle())
        with self.assertRaisesRegex(c.RecoveryDenied, 'POSTBOOT_TOKEN_OWNER_MUST_BIND_SAME_RECOVERY_LIFECYCLE'):
            self.resume()
        self.assertNotIn('database', [item[0] for item in self.calls])

    def test_database_scope_drift_or_extra_field_cannot_enter_full_admission(self):
        for change in ({'readiness': {'fixture': 'different'}}, {'unexpected': True}):
            old = copy.deepcopy(self.native['database']); self.native['database'].update(change)
            with self.subTest(change=change), self.assertRaisesRegex(c.RecoveryDenied, 'SAME_REVIEWED_POSTBOOT_DATABASE_SCOPE'):
                self.resume()
            self.native['database'] = old
        self.assertNotIn('database', [item[0] for item in self.calls])

    def test_journal_mutation_or_revocation_during_composition_is_refused(self):
        self.mutate_during_database = True
        with self.assertRaisesRegex(c.RecoveryDenied, 'POSTBOOT_NATIVE_COMPOSITION_CHANGED'):
            self.resume()
        self.mutate_during_database = False; self.authority.active = False
        with self.assertRaisesRegex(c.RecoveryDenied, 'POSTBOOT_NATIVE_COMPOSITION_CHANGED'):
            self.resume()

    def test_read_only_reconciliation_can_resume_the_same_released_prefix(self):
        # Factory never treats cursor advancement alone as readiness; the actual
        # witness/owners remain the runtime boundary, including lost release ACK.
        self.row['nextStage'] = 9
        resumed = self.resume()
        self.assertIs(resumed.ports.lifecycle, self.life)
        self.assertEqual(self.calls[1], ('witness', {'stage': 'ACTIVE'}))
        self.assertEqual(self.row['nextStage'], 9)


if __name__ == '__main__':
    unittest.main()
