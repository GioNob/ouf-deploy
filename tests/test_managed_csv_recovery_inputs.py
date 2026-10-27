import copy
import importlib.util
import pathlib
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('capture', pathlib.Path(__file__).parents[1]/'tools/managed_csv_recovery/retained_inputs.py')
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)


def fixture(observations=None, pin=None, installed='/private/completed'):
    if observations is None:
        observations = {role: {'Id': digit*64, 'Image': 'sha256:'+digit*64, 'Name': '/'+role,
                              'State': {'Pid': pid, 'StartedAt': 'retained', 'Running': True, 'Paused': False, 'Restarting': False},
                              'Config': {'Env': ['PRIVATE_CANARY=not-output']}, 'HostConfig': {'Memory': 0},
                              'Mounts': [], 'NetworkSettings': {}}
                        for role, digit, pid in [('onboarding', 'a', 44), ('mcp', 'b', 45)]}
    pin = pin or (lambda pid: {'pid': pid, 'startTicks': 1, 'namespaces': {'net': [1, 2], 'mnt': [1, 3]}})
    cohort = {role: m.stable_binding(value) for role, value in observations.items()}
    cohort['onboarding'] = {**cohort['onboarding'], 'containerId': 'c'*64}
    review = {'schema': 'ouf.onboarding-profile-recovery-update-review.v1', 'executionRoot': installed, 'bootId': 'boot',
              'stages': ['VERIFY_CURRENT_ADMISSION', 'VERIFY_FINAL'],
              'nativePlan': {'proposal': {'existingApplications': cohort,
                                         'engineBinding': {'peerCredentials': [2, 0, 0]}}}}
    review_hash = m.digest(review)
    native_hash = m.digest(m.stable_binding(observations['onboarding']))
    result = {'schema': 'ouf.onboarding-profile-recovery-update-result.v1',
              'status': 'ONBOARDING_PROFILE_RECOVERY_UPDATE_INSTALLED_E2E_NOT_ACCEPTED', 'complete': True,
              'componentReadinessProven': True, 'contextPath': installed, 'reviewHash': review_hash,
              'authorityHash': 'd'*64, 'candidateSourceCommit': 'e'*40, 'nativeImageId': observations['onboarding']['Image'],
              'nativeBindingHash': native_hash, 'humanBudgetsGranted': 0, 'newGrantsGranted': 0, 'sourceActivations': 0,
              'acquisitionsExecuted': 0, 'registryWorkerTouched': False, 'automaticReplayAllowed': False, 'budgetReset': False,
              'counts': {'engineGets': 300, 'engineWrites': 8}}
    proof = {'nativeBindingHash': native_hash, 'generation': pin(observations['onboarding']['State']['Pid'])}
    journal = {'schema': 'ouf.onboarding-profile-recovery-update-journal.v1', 'state': 'COMPLETE',
               'reviewHash': review_hash, 'authorityHash': 'd'*64, 'quarantine': None, 'automaticReplayAllowed': False,
               'budgetReset': False, 'nextStage': 2,
               'effects': [{'stage': stage, 'state': 'APPLIED', 'intentHash': m.digest({'reviewHash': review_hash, 'stage': stage}),
                            'proof': proof if stage == 'VERIFY_FINAL' else {}} for stage in review['stages']],
               'candidates': {'onboarding': {'id': observations['onboarding']['Id'], 'configurationVerified': True,
                                            'readinessProven': True, 'generation': proof['generation']}}}
    case = {'schema': 'ouf.managed-csv-recovery-capture-case.v1', 'installedRoot': installed, 'reviewHash': review_hash,
            'authorityHash': 'd'*64, 'installedSource': 'e'*40, 'installedNativeImageId': result['nativeImageId'],
            'installedNativeBindingHash': native_hash, 'installedMcpNativeBindingHash': m.digest(cohort['mcp']),
            'installedMcpNativeImageId': observations['mcp']['Image'], 'cohortSize': len(cohort), 'targets': ['onboarding', 'mcp']}
    return review, result, journal, case, observations, pin


class FakeCapture:
    def __init__(self, documents):
        self.documents = documents; self.counts = {'privateMetadataReads': 0, 'engineGets': 0, 'bytes': 0}
        self.seals = {}; self.output = {}; self.root = pathlib.Path('/new-output'); self.maximums = {**m.MAXIMUMS, 'engineGets': 5}

    def private(self, path, expected=None):
        self.counts['privateMetadataReads'] += 1
        value = copy.deepcopy(self.documents[path.name])
        if expected is not None:
            m.require(m.digest(value) == expected, 'EXACT_INSTALLED_CAPTURE_HASH_REQUIRED')
        return value

    def put(self, name, value):
        self.output[name] = value


class CaptureTests(unittest.TestCase):
    def test_complete_cohort_observation_never_grants_authority(self):
        review, result, journal, case, observations, pin = fixture()
        capture = FakeCapture({'review.json': review, 'result.json': result, 'recovery.json': journal})

        class ReadOnlyEngine:
            def __init__(self, c, binding, ids):
                self.capture = c
                self.ids = set(ids)

            def get(self, path):
                self.capture.counts['engineGets'] += 1
                if path == '/v1.44/info':
                    return {'ServerVersion': '29.8.1'}
                return copy.deepcopy(next(value for value in observations.values() if path == '/v1.44/containers/'+value['Id']+'/json'))

        with tempfile.TemporaryDirectory() as directory:
            boot = pathlib.Path(directory)/'boot'; boot.write_text('boot')
            output = m.prepare(capture, case, engine_factory=ReadOnlyEngine, pin=pin, boot_path=boot)
        self.assertEqual(output['counts']['engineGets'], 5)
        self.assertEqual(output['counts']['privateMetadataReads'], 3)
        self.assertFalse(output['runtimeAuthorityIssued'])
        self.assertFalse(output['currentJobOrBudgetStateObserved'])
        self.assertNotIn('PRIVATE_CANARY', str(output))
        self.assertEqual(result['counts'], capture.output['inputs.json']['retainedInstallation']['counts'])

    def test_incomplete_claimed_or_foreign_receipts_are_refused(self):
        for key, mutation in [('result', lambda v: v.update(complete=False)),
                              ('result', lambda v: v.update(authorityHash='f'*64)),
                              ('result', lambda v: v.update(humanBudgetsGranted=1)),
                              ('journal', lambda v: v.update(state='OPEN')),
                              ('journal', lambda v: v['effects'][-1].update(state='CLAIMED')),
                              ('journal', lambda v: v['candidates']['onboarding'].update(readinessProven=False))]:
            with self.subTest(key=key, mutation=mutation):
                review, result, journal, case, _, _ = fixture()
                mutation(result if key == 'result' else journal)
                with self.assertRaises(m.Stop):
                    m.retained(review, result, journal, case)

    def test_foreign_mcp_binding_refused(self):
        review, result, journal, case, _, _ = fixture()
        case['installedMcpNativeBindingHash'] = 'f'*64
        with self.assertRaisesRegex(m.Stop, 'EXACT_RETAINED_MCP'):
            m.retained(review, result, journal, case)

    def test_engine_refuses_any_unselected_resource_before_dispatch(self):
        capture = FakeCapture({}); engine = m.Engine(capture, {}, ['a'*64, 'b'*64])
        for path in ['/v1.44/containers/json', '/v1.44/containers/'+'c'*64+'/json', '/v1.44/images/json']:
            with self.assertRaisesRegex(m.Stop, 'CLOSED_READ_ONLY_ENGINE'):
                engine.get(path)
        self.assertEqual(capture.counts['engineGets'], 0)

    def test_consumed_scope_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)/'scope'; root.mkdir(); marker = root/'existing'; marker.write_bytes(b'retain')
            from unittest.mock import patch
            with patch.object(m, 'ancestry'):
                with self.assertRaisesRegex(m.Stop, 'CONSUMED_NO_REPLAY'):
                    m.Capture(root, 2)
            self.assertEqual(marker.read_bytes(), b'retain')

    def test_live_peer_drift_is_refused(self):
        review, result, journal, case, observations, pin = fixture()
        capture = FakeCapture({'review.json': review, 'result.json': result, 'recovery.json': journal})

        class DriftEngine:
            def __init__(self, *args):
                pass

            def get(self, path):
                if path.endswith('/info'):
                    return {}
                value = copy.deepcopy(next(v for v in observations.values() if v['Id'] in path))
                if value['Name'] == '/mcp':
                    value['Config']['Env'] = ['changed']
                return value

        with tempfile.TemporaryDirectory() as directory:
            boot = pathlib.Path(directory)/'boot'; boot.write_text('boot')
            with self.assertRaisesRegex(m.Stop, 'RETAINED_PEER_GENERATION_CHANGED'):
                m.prepare(capture, case, engine_factory=DriftEngine, pin=pin, boot_path=boot)
        self.assertNotIn('inputs.json', capture.output)


if __name__ == '__main__':
    unittest.main()
