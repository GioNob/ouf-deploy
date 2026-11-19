import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_compiler import ROOT, c, fixture, io, modules

spec = importlib.util.spec_from_file_location('native_inputs', ROOT / 'native_inputs.py')
n = importlib.util.module_from_spec(spec);spec.loader.exec_module(n)


def inputs():
    values = fixture()
    review = c.build(io, modules['frozen_frames'], modules['frozen_replacement'], *values)
    snapshot = values[1];original = snapshot['runtimeBefore']['ingestion']
    for i, name in enumerate(('gateway', 'onboarding', 'mcp', 'udp', 'postgres'), 4):
        row = copy.deepcopy(original);row['Id'] = str(i) * 64;row['Config']['Hostname'] = row['Id'][:12]
        row['Name'] = '/' + name;snapshot['runtimeBefore'][name] = row
    before = snapshot['runtimeBefore'];binding_profile = 'ouf.runtime-binding.native-mount-order.v1'
    pins = {name: {'binding': io.stable(before[name]), 'restartCount': 0, 'bindingProfile': binding_profile}
            for name in ('onboarding', 'mcp', 'udp')}
    engine = {'socketPath': '/fixture/engine.sock', 'socketBinding': [1, 2, 0, 0, 0o600]}
    config = {'path': '/fixture/gateway.yaml', 'sha256': '7' * 64, 'metadata': [1] * 9,
              'ancestors': []}
    native = {'runtimeGuardProfile': {'unchangedApplications': pins}, 'engineBinding': engine,
              'ownerControlProfile': {'runtimeBinding': io.stable(before['onboarding']),
                 'runtimeBindingProfile': binding_profile, 'restartCount': 0},
              'databaseControlProfile': {'postgresRuntimeBinding': io.stable(before['postgres']),
                 'runtimeBindingProfile': binding_profile, 'postgresRestartCount': 0, 'engineBinding': engine},
              'imageImportProfile': {'engineBinding': engine, 'archive': {'old': 'do not reuse'}},
              'gatewayTransportProfile': {'config': config, 'fixture': True},
              'ingestionReadinessProfile': {'fixture': True},
              'packetBinding': {'path': '/fixture/old-packet', 'sha256': ''}}
    retained = {'executionReview': native, 'sourceClosure': {'frozen114': True}, 'issuerProfile': {'fixture': True}}
    routes = {str(i): {'id': str(i)} for i in range(80)}
    routes.update({key: {'id': key} for key in ('mcp-ingestion-status', 'mcp-ingestion-history')})
    packet = {'retainedGatewayConfig': {k: config[k] for k in ('path', 'sha256', 'metadata')},
              'routeDraft': {'afterRoutes': routes}}
    native['packetBinding']['sha256'] = io.digest(packet)
    review['candidateFileBindings'] = {name: {'path': '/fixture/' + name, 'sha256': '1' * 64}
                                      for name in snapshot['case']['files']}
    review['inputContext'] = '/fixture/input';review['inputSnapshotHash'] = io.digest(snapshot)
    snapshot['retainedReviewHash'] = 'review-sha';snapshot['retainedJournalHash'] = 'journal-sha'
    review['inputSnapshotHash'] = io.digest(snapshot)
    return review, snapshot, retained, packet, values[-1]


class NativeInputsTests(unittest.TestCase):
    def test_one_ingestion_scope_and_existing_gateway_profiles_only(self):
        values = inputs();original = copy.deepcopy(values)
        result = n.project(io, *values)
        self.assertEqual(values, original)
        contract = result['finiteIntentContract']
        self.assertEqual(len(contract['stages']), 12)
        self.assertEqual(contract['maximumEnginePosts'], 7)
        self.assertEqual(contract['maximumGatewayWrites'], 0)
        self.assertEqual(contract['maximumSecretCreations'], 0)
        self.assertFalse(result['historicalQualificationReusableForNewExecutor'])
        self.assertFalse(result['nativeRuntimeExecutorQualified'])
        self.assertEqual(set(result['unchangedApplications']), {'gateway', 'onboarding', 'mcp', 'udp'})
        self.assertEqual(result['imageImportProfile']['archive'], values[0]['candidateFileBindings']['image.tar.gz'])
        self.assertEqual(result['unchangedGatewayRoutes'], values[3]['routeDraft']['afterRoutes'])

    def test_gateway_writes_extra_stage_reordering_and_authority_flags_block(self):
        for mutation in ('gateway', 'key', 'kind', 'order', 'intent', 'authority', 'activation', 'bool_counter'):
            values = inputs();review = values[0]
            if mutation == 'gateway': review['stages'][2]['name'] = 'gateway.STOP_OLD'
            if mutation == 'key': review['stages'].insert(1, {'name': 'CREATE_DEDICATED_KEY'})
            if mutation == 'kind': review['stages'][0]['kind'] = 'EFFECT'
            if mutation == 'order': review['stages'].reverse()
            if mutation == 'intent': review['stages'][2]['intent']['oldContainerId'] = 'changed'
            if mutation == 'authority': review['runtimeAuthorityIssued'] = True
            if mutation == 'activation': review['sourceActivationAllowed'] = True
            if mutation == 'bool_counter': review['gatewayWrites'] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                n.project(io, *values)

    def test_foreign_runtime_engine_config_or_candidate_never_enters_profiles(self):
        for mutation in ('owner', 'postgres', 'engine', 'config', 'image', 'same_generation'):
            values = inputs();review, snapshot, retained, packet, candidate = values
            native = retained['executionReview']
            if mutation == 'owner': snapshot['runtimeBefore']['onboarding']['Config']['User'] = '0'
            if mutation == 'postgres': snapshot['runtimeBefore']['postgres']['State']['Pid'] += 1
            if mutation == 'engine': native['imageImportProfile']['engineBinding'] = {'other': True}
            if mutation == 'config': native['gatewayTransportProfile']['config']['sha256'] = '9' * 64
            if mutation == 'image': candidate['Id'] = 'sha256:' + '9' * 64
            if mutation == 'same_generation': snapshot['runtimeBefore']['gateway']['Id'] = review['oldContainerId']
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                n.project(io, *values)

    def test_support_tamper_blocks_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'compiler.py').write_text('raise RuntimeError("must not execute")')
            with self.assertRaisesRegex(ValueError, 'QUALIFIED_REVIEW_COMPILER_REQUIRED'):
                n.load(Path(tmp))

    def test_private_bundle_is_inert_and_cannot_be_recreated(self):
        review, snapshot, retained, packet, candidate = inputs()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = {'schema': 'ouf.readiness-patch-native-input-case.v1', 'snapshotRoot': str(root),
                    'reviewContext': '/fixture/review', 'reviewHash': io.digest(review),
                    'inputSnapshotHash': io.digest(snapshot)}
            completed = {'reviewHash': io.digest(review), 'complete': True, 'runtimeAuthorityIssued': False}
            def read(path, pin=None, root_owned=False):
                name = str(path)
                if name == '/fixture/review/review.json': value = review
                elif name == '/fixture/review/complete.json': value = completed
                elif name.endswith('/snapshot.json'): value = snapshot
                elif name.endswith('/review.json'): value = retained
                elif name.endswith('/recovery.json'): value = {'complete': True}
                elif name == '/fixture/old-packet': value = packet
                elif name.endswith('/image-inspect.json'): value = [candidate]
                else: raise AssertionError('unexpected file read')
                return value, io.encoded(value)
            original = Path.lstat
            def owned(path):
                s = original(path)
                return SimpleNamespace(st_uid=0, st_mode=s.st_mode) if path == root else s
            def binding(_, path, sha, maximum):
                return {'path': str(path), 'sha256': sha}
            with patch.object(io, 'read_json', read), patch.object(Path, 'lstat', owned), \
                    patch.object(c, 'binding', binding), \
                    patch('socket.socket', side_effect=AssertionError('network')):
                result = n.run(c, modules, case)
                self.assertEqual(result['engineRequests'], 0)
                self.assertFalse(result['nativeRuntimeExecutorQualified'])
                self.assertNotIn('private-fixture-value', json.dumps(result))
                bundle = Path(result['contextPath']) / 'native-inputs.json'
                self.assertIn('private-fixture-value', bundle.read_text())
                before = bundle.read_bytes()
                with self.assertRaisesRegex(ValueError, 'NATIVE_INPUT_CONTEXT_EXISTS_DO_NOT_REPLAY'):
                    n.run(c, modules, case)
                self.assertEqual(bundle.read_bytes(), before)
                bad_case = {**case, 'reviewHash': 'f' * 64}
                with self.assertRaisesRegex(ValueError, 'EXACT_COMPLETED_PATCH_REVIEW_REQUIRED'):
                    n.run(c, modules, bad_case)
                self.assertEqual(len(list(root.iterdir())), 1)


if __name__ == '__main__':
    unittest.main()
