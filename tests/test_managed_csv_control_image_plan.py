import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

BASE = Path(__file__).parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


m = load('control_plan', BASE/'tools/managed_csv_recovery/image_plan.py')
p = load('retained_plan_helper', BASE/'tools/acquisition_read_native/plan_helper.py')
mac = load('retained_mac', BASE/'tools/acquisition_read_native/retained_mac.py')


def fixture(root=Path('/fixture'), receipts=None):
    receipts = receipts or {role: m.decode((BASE/('releases/managed-profile-control-'+role+'-image-custody-20261027.json')).read_bytes())
                            for role in ('onboarding', 'mcp')}
    observations = {}; network_id = 'f'*64
    for i, role in enumerate(['onboarding', 'mcp']+['other'+str(n) for n in range(11)], 1):
        config = copy.deepcopy(receipts[role]['imageAudit']['imageConfig']) if role in receipts else {
            'User': '10001', 'Env': [], 'Entrypoint': ['fixture'], 'Cmd': None, 'Labels': {}}
        config.setdefault('Env', []); config.setdefault('Labels', {})
        # Captured container Config is the create API projection, not the OCI
        # image metadata (Linux does not pass image ArgsEscaped into create).
        config['ArgsEscaped'] = False
        config['Hostname'] = 'retained-'+role
        if role == 'mcp':
            config['Env'] += ['MCP_OIDC_TOKEN_ENDPOINT=https://issuer.example/token', 'MCP_OIDC_CLIENT_ID=fixture',
                              'MCP_OIDC_CLIENT_SECRET_FILE=/private/not-read']
        cid = ('%064x' % i); key = 'onboarding' if role == 'onboarding' else 'peer-'+cid[:16]
        # Keep unique16-prefix keys, just as the actual producer does.
        cid = ('%016x' % i)+'a'*48; key = 'onboarding' if role == 'onboarding' else 'peer-'+cid[:16]
        observations[key] = {'Id': cid, 'Image': 'sha256:'+('%064x' % (100+i)), 'Name': '/'+role,
                             'State': {'Running': True, 'Paused': False, 'Restarting': False, 'Pid': 100+i, 'StartedAt': 'retained'},
                             'Config': config, 'HostConfig': {'AutoRemove': False, 'Memory': 0, 'OomKillDisable': None,
                                  'RestartPolicy': {'Name': 'unless-stopped', 'MaximumRetryCount': 0},
                                  'NetworkMode': 'ouf-ci', 'PortBindings': {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '0'}]}},
                             'Mounts': [], 'NetworkSettings': {'Ports': {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(18000+i)}]},
                                  'Networks': {'ouf-ci': {'NetworkID': network_id, 'Aliases': [role], 'MacAddress': '02:00:00:00:00:%02x' % i,
                                                       'IPAddress': '172.30.0.%d' % (i+1), 'IPAMConfig': None}}}}
    targets = {'onboarding': 'onboarding', 'mcp': next(key for key, value in observations.items() if value['Name'] == '/mcp')}
    inputs = {'schema': 'ouf.managed-csv-recovery-current-inputs.v1', 'bootId': 'fixture-boot', 'engineBinding': {'fixture': True},
              'engineInfo': {'ServerVersion': '29.8.1', 'DriverStatus': [['driver-type', 'io.containerd.snapshotter.v1']]},
              'currentObservations': observations, 'currentProcessPins': {key: {'pid': value['State']['Pid']} for key, value in observations.items()},
              'currentRootProcessPins': {'pid1': {'pid': 1}, 'engine': {'pid': 2}}, 'targets': ['onboarding', 'mcp'],
              'resolvedTargetRoles': targets, 'counts': {'bytes': 670087, 'engineGets': 27, 'privateMetadataReads': 5},
              'captureAccounting': {'currentScopeCounts': {'bytes': 670087, 'engineGets': 27, 'privateMetadataReads': 5},
                                    'retainedConsumedScopeCounts': {'bytes': 483676, 'engineGets': 0, 'privateMetadataReads': 3},
                                    'cumulativeCounts': {'bytes': 1153763, 'engineGets': 27, 'privateMetadataReads': 8}},
              'currentJobOrBudgetStateObserved': False, 'runtimeAuthorityIssued': False, 'automaticReplayAllowed': False, 'budgetReset': False}
    result = {'complete': True, 'inputsHash': m.digest(inputs), 'contextPath': str(root/'capture'), 'runtimeAuthorityIssued': False,
              'counts': inputs['counts'], 'captureAccounting': inputs['captureAccounting'], 'targetRoles': inputs['targets']}
    proposal = {'engineBinding': inputs['engineBinding'],
                'onboardingReplacement': {'request': p.config_copy(observations['onboarding']),
                                         'readiness': {'readinessPort': 8080, 'readinessPath': '/actuator/health/readiness'}},
                'candidateApplicationFacts': copy.deepcopy(receipts['onboarding']['application']),
                'boundDatabaseProfile': {'schema': 'ouf.current-onboarding-database-snapshot-profile.v1'},
                'nativeFlywayConfiguration': {'fixtureMetadataOnly': True}}
    review = {'schema': 'ouf.onboarding-profile-recovery-update-review.v1', 'bootId': inputs['bootId'], 'nativePlan': {'proposal': proposal}}
    case = {'captureResult': result, 'captureHash': result['inputsHash'], 'captureRoot': str(root/'capture'),
            'retainedReviewPath': str(root/'review.json'), 'retainedReviewHash': m.digest(review)}
    archives = {role: {'path': '/fixture/'+role+'-native.tar'} for role in receipts}
    return inputs, result, review, receipts, archives, case


class PlanTests(unittest.TestCase):
    def compile(self, values):
        inputs, result, review, receipts, archives, case = values
        return m.compile_plan(inputs, result, review, receipts, archives, p, mac, case)

    def test_exact_two_target_plan_preserves_cohort_and_has_no_authority(self):
        values = fixture(); before = copy.deepcopy(values)
        plan = self.compile(values)
        self.assertEqual(values, before)
        self.assertEqual(len(plan['existingApplications']), 13)
        self.assertEqual(len(plan['unchangedApplications']), 11)
        self.assertEqual(set(plan['replacements']), {'onboarding', 'mcp'})
        self.assertEqual(plan['databaseMigration'], {'from': 36, 'to': 36, 'newMigrations': 0})
        for key in ('runtimeAuthorityIssued', 'targetApplyAuthorized', 'executionEntryQualified', 'humanBudgetsOrResumeAuthorized'):
            self.assertFalse(plan[key])

    def test_retained_ip_mac_published_port_memory_and_env_are_preserved(self):
        values = fixture(); plan = self.compile(values); inputs = values[0]
        for role, replacement in plan['replacements'].items():
            old = inputs['currentObservations'][inputs['resolvedTargetRoles'][role]]; request = replacement['request']
            endpoint = request['NetworkingConfig']['EndpointsConfig']['ouf-ci']
            actual = old['NetworkSettings']['Networks']['ouf-ci']
            self.assertEqual(endpoint['MacAddress'], actual['MacAddress'])
            self.assertEqual(endpoint['IPAMConfig']['IPv4Address'], actual['IPAddress'])
            self.assertEqual(request['HostConfig']['PortBindings'], old['NetworkSettings']['Ports'])
            self.assertEqual(request['Env'], old['Config']['Env'])
            self.assertEqual(request['HostConfig']['Memory'], 0)
            self.assertEqual(replacement['runtimeHostProjection']['retainedMemoryBytes'], 0)

    def test_capture_tampering_stops_before_compiling_replacements(self):
        values = list(fixture()); values[0]['currentObservations']['onboarding']['Config']['User'] = '0'
        with self.assertRaisesRegex(m.Stop, 'EXACT_METADATA_ONLY_CAPTURE'):
            self.compile(values)

    def test_migration_or_packaged_yaml_drift_cannot_be_authorized(self):
        for field in ('migrations', 'applicationYamlSha256'):
            values = list(fixture()); values[2]['nativePlan']['proposal']['candidateApplicationFacts'][field] = [] if field == 'migrations' else '0'*64
            values[5]['retainedReviewHash'] = m.digest(values[2])
            with self.assertRaisesRegex(m.Stop, 'ALL_36_INSTALLED_MIGRATIONS'):
                self.compile(values)

    def test_new_image_env_or_non_oci_labels_are_rejected(self):
        for kind in ('env', 'label'):
            values = list(fixture())
            image = values[3]['mcp']['imageAudit']['imageConfig']
            if kind == 'env':
                image['Env'] = [*(image.get('Env') or []), 'UNREVIEWED_DEFAULT=value']
            else:
                image.setdefault('Labels', {})['unreviewed.label'] = 'value'
            with self.assertRaisesRegex(m.Stop, 'NO_NEW_IMAGE_ENV|NO_UNREVIEWED_IMAGE_LABEL'):
                self.compile(values)

    def test_wrong_zip_is_rejected_before_unzip(self):
        class StubScope:
            counts = {'ciZipReads': 0, 'nativeArchivesPrepared': 0}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); StubScope.root = root; source = root/'bad.zip'; source.write_bytes(b'wrong')
            from unittest.mock import patch
            with patch.object(m.os, 'geteuid', return_value=0):
                with self.assertRaisesRegex(m.Stop, 'PROTECTED_EXACT_CI_ZIP'):
                    m.stage_native(StubScope, 'onboarding', source, fixture()[3]['onboarding'], lambda *_: self.fail('unpack reached'), None)

    def test_nondefault_unsupported_captured_config_is_not_ignored(self):
        values = list(fixture()); key = values[0]['resolvedTargetRoles']['mcp']
        values[0]['currentObservations'][key]['Config']['ArgsEscaped'] = True
        values[5]['captureHash'] = values[1]['inputsHash'] = m.digest(values[0])
        with self.assertRaisesRegex(p.Stop, 'NONDEFAULT_UNSUPPORTED_CONTAINER_CONFIG'):
            self.compile(values)

    def test_failed_metadata_digest_still_counts_the_read_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root/'input.json'; path.write_bytes(b'{"wrong":true}'); path.chmod(0o400)
            scope = m.Scope.__new__(m.Scope); scope.root = root
            scope.counts = {'privateMetadataReads': 0, 'privateMetadataBytes': 0}; scope.seals = []
            from unittest.mock import patch
            with patch.object(m, 'ancestry'):
                with self.assertRaisesRegex(m.Stop, 'EXACT_CAPTURE_METADATA_HASH'):
                    scope.private(path, '0'*64)
            self.assertEqual(scope.counts['privateMetadataReads'], 1)
            self.assertEqual(scope.counts['privateMetadataBytes'], len(path.read_bytes()))


if __name__ == '__main__':
    unittest.main()
