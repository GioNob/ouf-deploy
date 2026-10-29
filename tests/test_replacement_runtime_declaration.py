import copy
import ast
import hashlib
import importlib.util
import re
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('declaration', Path(__file__).parent.parent / 'scripts/compile-replacement-runtime-declaration.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RuntimeDeclaration(unittest.TestCase):
    def setUp(self):
        self.mounts = [{'source': '/root/inputs/' + n, 'target': '/run/inputs/' + n,
                        'uid': 10001, 'gid': 10001, 'mode': 0o400, 'readOnly': True,
                        'sha256': str(i) * 64, 'secretBytesFreshlyVerified': False}
                       for i, n in enumerate(('credential', 'mac', 'trust'), 1)]
        self.original = {
            'Id': 'a' * 64, 'Image': 'sha256:' + 'b' * 64,
            'Config': {'Env': ['PRIVATE_FIXTURE=not-real'], 'Labels': {'owner': 'fixture'}},
            'HostConfig': {'Privileged': False, 'NetworkMode': 'fixture-bridge',
                           'Binds': ['/root/auth:/run/auth:ro'], 'ReadonlyRootfs': True,
                           'CapDrop': ['ALL'], 'Memory': 536870912, 'PidsLimit': 128,
                           'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                           'LogConfig': {'Type': 'json-file', 'Config': {'max-size': '10m'}},
                           'Mounts': [], 'SecurityOpt': ['no-new-privileges'],
                           'FutureEngineField': {'preserved': ['in', 'full']}},
            'Mounts': [{'Type': 'bind', 'Source': '/root/auth', 'Destination': '/run/auth', 'RW': False}],
            'State': {'Pid': 42, 'Running': True, 'StartedAt': 'fixture-generation'},
            'NetworkSettings': {'Networks': {'fixture-bridge': {'IPAddress': '172.18.0.6',
                                                            'Aliases': ['semantic'], 'NetworkID': 'c' * 64}}}}
        draft = {'candidateConfig': {'User': '10001:10001', 'Env': ['SECRET_FILE=/run/inputs/credential']},
                 'retainedContainer': self.original, 'retainedAuthMounts': [{'readOnly': True}],
                 'newReadOnlyMounts': [{k: v for k, v in x.items() if k not in ('sha256', 'secretBytesFreshlyVerified')} for x in self.mounts],
                 'applyAuthorized': False}
        self.intake = {'productionApplyReady': False, 'replacementConfigurationDraft': draft,
                       'originalProviderBinding': {'private-fixture': 'not-real'}, 'runtimeInputManifest': {'mountsInstalled': False}}
        self.contract = {'schema': 'ouf.discovery.private-application-input-contract.v1',
                         'protectedIntakeHash': m.INTAKE_HASH, 'candidateConfig': copy.deepcopy(draft['candidateConfig']),
                         'retainedConsultationMounts': copy.deepcopy(draft['retainedAuthMounts']),
                         'roleOwnedReadOnlyMounts': copy.deepcopy(self.mounts),
                         'originalProviderBinding': copy.deepcopy(self.intake['originalProviderBinding']),
                         'runtimeInputManifest': copy.deepcopy(self.intake['runtimeInputManifest']),
                         'productionApplyReady': False, 'applicationCutoverAuthorized': False,
                         'completeReplacementOciProven': False}

    def test_preserves_all_host_fields_and_full_original_evidence(self):
        before = copy.deepcopy(self.intake)
        plan, report = m.compile_declaration(self.intake, self.contract)
        self.assertEqual(self.intake, before)
        self.assertEqual(plan['retainedNativeCreationFrame'], self.original)
        host = plan['proposedHostConfig']
        for key, value in self.original['HostConfig'].items():
            if key != 'Binds':
                self.assertEqual(host[key], value)
        self.assertEqual(host['Binds'][0], '/root/auth:/run/auth:ro')
        self.assertEqual(len(host['Binds']), 4)
        self.assertTrue(all(x.endswith(':ro') for x in host['Binds']))
        self.assertTrue(report['hostFieldsPreservedExceptDeclaredBindAppend'])

    def test_no_historical_declaration_promotes_authority_or_liveness(self):
        plan, report = m.compile_declaration(self.intake, self.contract)
        for value in (plan, report):
            for key in ('productionApplyReady', 'applicationCutoverAuthorized', 'completeReplacementOciProven'):
                self.assertIs(value[key], False)
            self.assertIs(value['observationsAreHistorical'], True)
        self.assertIn('EXPLICIT_COORDINATED_TRANSITION_AUTHORITY_NO_R9_REPLAY', plan['requiredBeforeMutation'])
        self.assertNotIn('PRIVATE_FIXTURE', str(report))
        self.assertNotIn('/root/inputs', str(report))

    def test_contract_or_protected_binding_drift_denied(self):
        for key in ('candidateConfig', 'retainedConsultationMounts', 'originalProviderBinding', 'runtimeInputManifest'):
            value = copy.deepcopy(self.contract)
            value[key] = {}
            with self.assertRaises(ValueError):
                m.compile_declaration(self.intake, value)

    def test_existing_mount_collision_and_parent_shadowing_denied(self):
        for target in ('/run/auth', '/run', '/run/auth/nested'):
            intake, contract = copy.deepcopy(self.intake), copy.deepcopy(self.contract)
            intake['replacementConfigurationDraft']['newReadOnlyMounts'][0]['target'] = target
            contract['roleOwnedReadOnlyMounts'][0]['target'] = target
            with self.assertRaisesRegex(ValueError, 'MOUNT'):
                m.compile_declaration(intake, contract)

    def test_writable_wrong_owner_unreviewed_and_duplicate_new_mounts_denied(self):
        for key, value in [('readOnly', False), ('uid', 0), ('mode', 0o600), ('target', '/unreviewed')]:
            contract = copy.deepcopy(self.contract)
            contract['roleOwnedReadOnlyMounts'][0][key] = value
            with self.assertRaises(ValueError):
                m.compile_declaration(self.intake, contract)
        intake, contract = copy.deepcopy(self.intake), copy.deepcopy(self.contract)
        target = contract['roleOwnedReadOnlyMounts'][0]['target']
        intake['replacementConfigurationDraft']['newReadOnlyMounts'][1]['target'] = target
        contract['roleOwnedReadOnlyMounts'][1]['target'] = target
        with self.assertRaises(ValueError):
            m.compile_declaration(intake, contract)

    def test_unsafe_host_scope_and_stopped_source_denied(self):
        for key, value in [('Privileged', True), ('NetworkMode', 'host'), ('NetworkMode', 'container:other'), ('ContainerIDFile', '/tmp/pid')]:
            intake = copy.deepcopy(self.intake)
            intake['replacementConfigurationDraft']['retainedContainer']['HostConfig'][key] = value
            with self.assertRaises(ValueError):
                m.compile_declaration(intake, self.contract)
        intake = copy.deepcopy(self.intake)
        intake['replacementConfigurationDraft']['retainedContainer']['State']['Running'] = False
        with self.assertRaises(ValueError):
            m.compile_declaration(intake, self.contract)

    def test_bind_path_injection_and_root_candidate_denied(self):
        for path in ('/root/input:rw', '/root/../input', '/root/input\nother'):
            intake, contract = copy.deepcopy(self.intake), copy.deepcopy(self.contract)
            intake['replacementConfigurationDraft']['newReadOnlyMounts'][0]['source'] = path
            contract['roleOwnedReadOnlyMounts'][0]['source'] = path
            with self.assertRaises(ValueError):
                m.compile_declaration(intake, contract)
        intake, contract = copy.deepcopy(self.intake), copy.deepcopy(self.contract)
        intake['replacementConfigurationDraft']['candidateConfig']['User'] = '0'
        contract['candidateConfig']['User'] = '0'
        with self.assertRaises(ValueError):
            m.compile_declaration(intake, contract)

    def test_operator_delivery_checks_the_exact_bytes_before_root_execution(self):
        root = Path(__file__).parent.parent
        launcher = (root / 'releases/replacement-runtime-declaration-20261010.sh').read_text()
        expected = ast.literal_eval(re.search(r'expected=(\([^\n]+\))', launcher).group(1))
        paths = ['scripts/compile-replacement-runtime-declaration.py',
                 'tools/semantic_target_review/prepare_application_runtime_inputs.py']
        self.assertEqual(expected, tuple(hashlib.sha256((root / p).read_bytes()).hexdigest() for p in paths))
        self.assertEqual(launcher.count('?ref=c80b7584a1b7f403c3ecf113c2c4debad1de405e'), 2)
        self.assertIn('sudo /usr/bin/python3 -I -B -c', launcher)
        self.assertIn('compile(sources[0]', launcher)
        self.assertNotIn('exec(compile(pathlib', launcher)


if __name__ == '__main__':
    unittest.main()
