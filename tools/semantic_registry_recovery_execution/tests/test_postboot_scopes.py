"""Pure postboot composition contract against the production scope builders.

Native collaborators and the FileOnlyProfile are explicit data fixtures. The
actual function bodies are isolated with AST because this partial checkout may
lack the historical native import closure. No runtime custody, crypto, issuer,
Docker or target admission is qualified by these tests.
"""
import ast
import copy
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest

from tools.semantic_registry_recovery_execution import core as c
from tools.semantic_registry_recovery_composition.compose import candidate_contract, GATES
from tools.semantic_registry_postboot_owner import contract as owner_contract
from tools.semantic_registry_postboot_owner.tests.fixture import make_context
from tools.semantic_policy_token_owner.producer import Binding

SOURCE = Path(__file__).resolve().parents[1]


class ImportFree(ast.NodeTransformer):
    def visit_ImportFrom(self, node):
        return None


def load_parts(path, names, namespace):
    tree = ast.parse(Path(path).read_text())
    selected = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names:
            selected.append(node)
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets):
            selected.append(node)
    tree.body = selected
    tree = ImportFree().visit(tree)
    exec(compile(tree, str(path), 'exec'), namespace)
    return namespace


class DataProfile:
    def __init__(self, request, configtree):
        self.request, self.configtree = copy.deepcopy(request), copy.deepcopy(configtree)
        self.sha256 = c.digest({'request': request, 'configtree': configtree})

    def verify(self, request):
        c.require(request == self.request, 'FIXTURE_RETAINED_REQUEST_CHANGED')
        return self.sha256


def scopes_module():
    # Each scope builder is the unedited production function body. Only the
    # private metadata validator/profile type are explicit unit substitutes.
    env = dict(require=c.require, digest=c.digest, validate_plan=c.validate_plan,
               Path=Path, re=re, SimpleNamespace=SimpleNamespace, Binding=Binding,
               compile_scope=owner_contract.compile_scope, OWNER_SCOPE=owner_contract.SCOPE,
               profile_type=lambda: DataProfile,
               private_file=SimpleNamespace(validate=lambda binding, **kw: None))
    for file, names in (
        ('authorization.py', {'scope'}),
        ('factory.py', {'FIELDS', 'canonical_root', 'factory_scope'}),
        ('read_budget.py', {'LIMITS', 'read_scope'}),
        ('bootstrap.py', {'PREFIX', 'bootstrap_scope', 'installation_scope'}),
        ('node_owner.py', {'node_scope'}),
        ('database.py', {'database_scope'}),
        ('gateway.py', {'gateway_scope'}),
        ('semantic_request.py', {'CLIENT_SOURCE', 'OBSERVABLE_NON_SUCCESS', 'request_scope'}),
        ('admission.py', {'admission_scope'}),
    ):
        load_parts(SOURCE/file, names, env)
    transport = load_parts(SOURCE.parent/'semantic_live_route_diagnostic/reader.py', {'OPERATION'}, {})
    env['transport'] = SimpleNamespace(OPERATION=transport['OPERATION'])
    env['recovery_scope'] = env['scope']
    load_parts(SOURCE/'postboot_scopes.py', {'KEYS', 'compile_scopes'}, env)
    return SimpleNamespace(**env)


class PostbootScopes(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=SOURCE.parents[1]); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        proposal = {'registry': {'containerId': 'a'*64}, 'requiredGates': list(GATES), 'unresolvedGateCount': 8}
        plan = candidate_contract(proposal, 'b'*64, 'c'*64)
        output = self.root/'tokens'; output.mkdir(mode=0o750)
        secret = self.root/'credential'; secret.write_bytes(b'DISPOSABLE'); secret.chmod(0o400)
        binding = Binding('https://fixture.invalid/token', 'fixture', 'authorization.bundle.read', str(output), 'token.jwt', 10001)
        self.boot = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        recovery = {'planHash': c.digest(plan), 'logicalOperationRef': plan['logicalOperationRef'],
                    'registryId': 'a'*64, 'bootId': self.boot}
        self.owner = make_context(self.root/'metadata', binding, {}, 'd'*64, secret, recovery, 'e'*64,
            source_paths={name: Path(owner_contract.__file__) for name in owner_contract.SOURCE_FILES})
        identity = self.owner['ownerInputs']['outputDirectoryIdentity']
        token = {'source': str(output), 'target': '/run/policy', 'fileName': 'token.jwt', 'gid': 10001,
                 'directoryDevice': identity['device'], 'directoryInode': identity['inode'],
                 'ownerBindingHash': binding.digest(), 'maxBytes': 16384, 'minimumRemainingSeconds': 90}
        recipe = {'sourceClosureHash': 'e'*64, 'renewableToken': token,
                  'expectedRootfsSeal': 'f'*64, 'independentFixtureRecipe': True}
        self.profile = DataProfile({'Image': 'sha256:'+'1'*64}, {'source': '/fixture/db'})
        self.registry = {'creationRequest': self.profile.request, 'configtree': self.profile.configtree,
            'readinessScope': {'database': 'fixture'}, 'imageAudit': {'independentFixtureAudit': True},
            'nodeRecipe': copy.deepcopy(recipe)}
        self.registry['nodeRecipe']['sourceClosureHash'] = '2'*64
        self.registry['nodeRecipe']['renewableToken'].pop('directoryDevice')
        self.registry['nodeRecipe']['renewableToken'].pop('directoryInode')
        retained = {'path': str(self.root/'history/inputs.json'), 'sha256': '3'*64}
        self.m = scopes_module()
        self.native = {'schema': 'ouf.semantic-registry-recovery-native-context.v1',
            'retainedInputs': retained, 'plan': plan,
            'engineBinding': {'socketPath': '/fixture/docker.sock', 'socketBinding': [1,2,0,0,384]},
            'stoppedSnapshot': {'fixture': 'stopped'}, 'nodeRecipe': recipe,
            'database': {'readiness': self.registry['readinessScope'], 'postgres': {'fixture': 'pg'}, 'program': {'fixture': 'docker'}},
            'gateway': {'pin': {'fixture': 'gateway'}, 'profile': {'fixture': 'admin'}, 'routes': {'fixture': {}}, 'networkId': '4'*64},
            'originalRequest': {'fixture': 'frozenReferences'},
            'executionRoot': str(self.m.canonical_root(retained['path'], plan['logicalOperationRef']))}

    def compile(self):
        return self.m.compile_scopes(self.native, self.owner, self.registry, self.profile, self.boot)

    def test_complete_scopes_equal_runtime_constructor_scope_builders(self):
        before = copy.deepcopy((self.native, self.owner, self.registry))
        scopes = self.compile(); m = self.m
        life = SimpleNamespace(plan=self.native['plan'], engine=SimpleNamespace(
            path=self.native['engineBinding']['socketPath'], binding=tuple(self.native['engineBinding']['socketBinding'])))
        db = self.native['database']; gw = self.native['gateway']
        database = SimpleNamespace(lifecycle=life, scope=m.database_scope(life, db['readiness'], db['postgres'], db['program'], self.registry['imageAudit']))
        node = SimpleNamespace(scope=m.node_scope(life.plan, self.native['nodeRecipe'], self.profile),
            token_owner=SimpleNamespace(binding=Binding(**self.owner['ownerInputs']['binding'])))
        gateway = SimpleNamespace(lifecycle=life, scope=m.gateway_scope(life, gw['pin'], gw['profile'], gw['routes'], gw['networkId']))
        self.assertEqual(set(scopes), m.KEYS)
        self.assertEqual(scopes['semanticRegistryRecovery'], m.recovery_scope(life.plan))
        self.assertEqual(scopes['semanticRegistryRecoveryFactory'], m.factory_scope(self.native))
        self.assertEqual(scopes['semanticRegistryRecoveryReads'], m.read_scope(life.plan, self.native['executionRoot']))
        self.assertEqual(scopes['semanticRegistryRecoveryDatabase'], database.scope)
        self.assertEqual(scopes['semanticRegistryRecoveryNode'], node.scope)
        self.assertEqual(scopes['semanticRegistryRecoveryGateway'], gateway.scope)
        self.assertEqual(scopes['semanticRegistryRecoveryAdmission'], m.admission_scope(database, node))
        self.assertEqual(scopes['semanticRegistryRecoveryOriginalRequest'], m.request_scope(gateway, self.native['originalRequest']))
        self.assertEqual(scopes['semanticRegistryPostbootBootstrap'], m.bootstrap_scope(life.plan, self.registry['creationRequest'], self.profile, self.boot))
        self.assertEqual(scopes['semanticRegistryPostbootInstallation'], m.installation_scope(self.native, self.registry['creationRequest'], self.profile, self.boot))
        self.assertEqual(scopes[owner_contract.SCOPE], owner_contract.compile_scope(self.owner))
        self.assertEqual(before, (self.native, self.owner, self.registry))
        self.assertFalse(scopes['semanticRegistryPostbootBootstrap']['javaReleaseAllowed'])
        self.assertFalse(scopes['semanticRegistryRecoveryAdmission']['tokenAcquisitionAllowed'])
        self.assertFalse(scopes['semanticRegistryPostbootInstallation']['runtimeEffectsAllowed'])

    def test_independent_recipe_drift_is_refused(self):
        self.native['nodeRecipe']['expectedRootfsSeal'] = '0'*64
        with self.assertRaisesRegex(c.RecoveryDenied, 'INDEPENDENT_IMAGE_RECIPE'):
            self.compile()

    def test_database_or_profile_drift_is_refused(self):
        self.native['database']['readiness'] = {'database': 'different'}
        with self.assertRaisesRegex(c.RecoveryDenied, 'PROFILE_AND_DATABASE'):
            self.compile()
        self.native['database']['readiness'] = self.registry['readinessScope']
        self.registry['configtree'] = {'source': '/fixture/other'}
        with self.assertRaisesRegex(c.RecoveryDenied, 'PROFILE_AND_DATABASE'):
            self.compile()

    def test_owner_other_plan_boot_or_source_cannot_be_composed(self):
        for field in ('planHash', 'registryId', 'bootId'):
            owner = copy.deepcopy(self.owner)
            owner['recovery'][field] = 'ffffffff-ffff-ffff-ffff-ffffffffffff' if field == 'bootId' else '0'*64
            with self.subTest(field=field), self.assertRaisesRegex(c.RecoveryDenied, 'ONE_POSTBOOT_OWNER'):
                self.m.compile_scopes(self.native, owner, self.registry, self.profile, self.boot)
        self.native['nodeRecipe']['sourceClosureHash'] = '0'*64
        with self.assertRaisesRegex(c.RecoveryDenied, 'ONE_POSTBOOT_OWNER'):
            self.compile()

    def test_other_output_or_inode_is_refused(self):
        for key, value in (('source', '/fixture/other'), ('fileName', 'other.jwt'), ('gid', 0),
                           ('directoryDevice', -1), ('directoryInode', -1), ('ownerBindingHash', '0'*64)):
            native = copy.deepcopy(self.native); native['nodeRecipe']['renewableToken'][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(c.RecoveryDenied, 'SAME_POSTBOOT_REGISTRY_TOKEN'):
                self.m.compile_scopes(native, self.owner, self.registry, self.profile, self.boot)

    def test_token_mount_target_and_read_limits_remain_independently_reviewed(self):
        for key, value in (('target', '/run/different'), ('maxBytes', 65536), ('minimumRemainingSeconds', 1)):
            native = copy.deepcopy(self.native); native['nodeRecipe']['renewableToken'][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(c.RecoveryDenied, 'RETAINED_POSTBOOT_TOKEN_MOUNT_CONTRACT'):
                self.m.compile_scopes(native, self.owner, self.registry, self.profile, self.boot)

    def test_scope_compilation_performs_no_runtime_or_authority_action(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.compile()
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()})


if __name__ == '__main__':
    unittest.main()
