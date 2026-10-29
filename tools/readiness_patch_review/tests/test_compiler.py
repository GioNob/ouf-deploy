import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('review_compiler', ROOT / 'compiler.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
modules = c.load_support(ROOT)
io, frames, replacement = (modules[n] for n in ('input_reader', 'frozen_frames', 'frozen_replacement'))


def fixture():
    old_id, current_id = 'a' * 64, 'b' * 64
    image_id, next_image = 'sha256:' + '3' * 64, 'sha256:' + '4' * 64
    defaults = {'User': '10002:10002', 'Entrypoint': ['java', '-jar', '/app/app.jar'],
                'WorkingDir': '/app', 'Env': ['JAVA_HOME=/java', 'PATH=/java/bin'],
                'Labels': {'org.opencontainers.image.revision': 'baseline'}, 'Cmd': None}
    network = {'fixture-net': {'NetworkID': 'e' * 64, 'Aliases': ['fixture-ingestion'],
                              'IPAMConfig': {'IPv4Address': '10.41.0.5'}, 'MacAddress': '06:00:00:00:00:05'}}
    config = {**copy.deepcopy(defaults), 'Image': image_id, 'Hostname': '',
              'Cmd': ['--spring.flyway.enabled=false', '--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY'],
              'Env': defaults['Env'] + ['API_KEY=private-fixture-value']}
    host = {'RestartPolicy': copy.deepcopy(frames.NO_RESTART), 'NetworkMode': 'fixture-net',
            'Binds': ['/fixture/owner.key:/run/owner.key:ro'], 'OomKillDisable': None}
    mounts = [{'Type': 'bind', 'Source': '/fixture/owner.key', 'Destination': '/run/owner.key', 'RW': False}]
    old_frame = {'schema': 'ouf.ingestion-local-docker-frame-template.v1', 'module': 'ingestion',
                 'name': 'fixture-ingestion', 'requestTemplate': {**copy.deepcopy(config),
                     'HostConfig': copy.deepcopy(host), 'NetworkingConfig': {'EndpointsConfig': copy.deepcopy(network)}},
                 'oldMounts': mounts, 'restoreRestartPolicy': {'Name': 'unless-stopped', 'MaximumRetryCount': 0},
                 'preserveObservedAddressesAndMacs': True, 'targetApplyAuthorized': False, 'runtimeAuthorityIssued': False}
    actual = {'Id': current_id, 'Name': '/fixture-ingestion', 'Image': image_id,
              'Platform': 'linux', 'Config': copy.deepcopy(config), 'HostConfig': copy.deepcopy(host),
              'Mounts': copy.deepcopy(mounts), 'NetworkSettings': {'Networks': copy.deepcopy(network)},
              'RestartCount': 0, 'State': {'Running': True, 'Status': 'running', 'Paused': False,
                  'Restarting': False, 'Dead': False, 'OOMKilled': False, 'Error': '', 'Pid': 1234, 'StartedAt': 'fixture-start'}}
    actual['Config']['Hostname'] = current_id[:12]
    actual['Config']['MacAddress'] = network['fixture-net']['MacAddress']
    actual['HostConfig']['RestartPolicy'] = copy.deepcopy(old_frame['restoreRestartPolicy'])
    endpoint = actual['NetworkSettings']['Networks']['fixture-net']
    endpoint.update(IPAddress='10.41.0.5', GlobalIPv6Address='')
    endpoint['Aliases'] += [current_id, current_id[:12]]
    candidate = {'Id': next_image, 'Config': copy.deepcopy(defaults), 'Os': 'linux', 'Architecture': 'amd64'}
    candidate['Config']['Labels']['org.opencontainers.image.revision'] = 'candidate'
    meta = {'sourceCommit': 'candidate', 'baselineSourceCommit': 'baseline', 'imageId': next_image,
            'imageArchiveSha256': '5' * 64, 'imageArchiveBytes': 1234, 'migrationChanges': 0}
    snapshot = {'candidateMetadata': meta, 'runtimeBefore': {'ingestion': actual,
                 'gateway': {'privateGatewayMarker': 'never-print-this'}}, 'observedAtUnix': 1,
                 'retainedReviewHash': 'review-hash', 'retainedJournalHash': 'row-hash',
                 'case': {'retainedContext': '/fixture-retained', 'files': {n: {'sha256': 'fixture', 'maximumBytes': 100}
                          for n in ('image.tar.gz', 'metadata.json', 'image-inspect.json', 'trivy-image.json')}}}
    stages = [{'name': 'ingestion.START_REPLACEMENT', 'intentHash': 'first'}]
    stages += [{'name': 'READ.' + str(i), 'intentHash': str(i)} for i in range(27)]
    row = {'nextStage': 28, 'budgetReset': False, 'effects': [
        {'stage': s['name'], 'intentHash': s['intentHash'], 'state': 'APPLIED'} for s in stages]}
    row['effects'][0]['nativeResource'] = {'containerId': current_id, 'pid': 1234, 'startedAt': 'fixture-start'}
    packet = {'frames': {'ingestion': old_frame}, 'candidate': {'imageConfig': defaults},
              'expectedRuntimeBindings': {'ingestion': {'containerId': old_id}}}
    review = {'executionReview': {'stages': stages, 'packetBinding': {'path': '/fixture-packet.json', 'sha256': io.digest(packet)}}}
    case = {'schema': 'ouf.readiness-patch-review-case.v1', 'candidateSourceCommit': 'candidate',
            'baselineSourceCommit': 'baseline', 'candidateImageId': next_image, 'oldIngestionId': current_id,
            'inputContext': '/fixture-input', 'inputCaseHash': io.digest(snapshot['case']),
            'imageDefaultCompatibilityProfile': c.IMAGE_INSPECT_PROFILE,
            'predecessorReviewCaseHash': '9' * 64, 'reconciledInputSnapshotHash': io.digest(snapshot)}
    return case, snapshot, review, row, packet, candidate


class ReviewTests(unittest.TestCase):
    def build(self, values):
        return c.build(io, frames, replacement, *values)

    def test_exact_frame_preserved_and_new_process_comparison_roundtrip(self):
        values = fixture()
        proposal = self.build(values)
        old_actual = values[1]['runtimeBefore']['ingestion']
        frame = proposal['frame']
        request = frame['requestTemplate']
        self.assertEqual(request['Env'], old_actual['Config']['Env'])
        self.assertEqual(request['HostConfig']['Binds'], old_actual['HostConfig']['Binds'])
        self.assertEqual(request['HostConfig']['RestartPolicy'], frames.NO_RESTART)
        self.assertEqual(frame['restoreRestartPolicy'], old_actual['HostConfig']['RestartPolicy'])
        self.assertNotIn('MacAddress', request)
        self.assertEqual(request['NetworkingConfig']['EndpointsConfig']['fixture-net']['MacAddress'], '06:00:00:00:00:05')
        self.assertEqual(request['Hostname'], '')
        new_id = 'c' * 64
        new = copy.deepcopy(old_actual)
        new.update(Id=new_id, Image=values[-1]['Id'])
        new['Config'] = {k: copy.deepcopy(v) for k, v in request.items() if k not in ('HostConfig', 'NetworkingConfig')}
        new['Config']['Hostname'] = new_id[:12]
        new['HostConfig'] = copy.deepcopy(request['HostConfig'])
        new['NetworkSettings']['Networks'] = copy.deepcopy(request['NetworkingConfig']['EndpointsConfig'])
        endpoint = new['NetworkSettings']['Networks']['fixture-net']
        endpoint.update(IPAddress='10.41.0.5', GlobalIPv6Address='')
        endpoint['Aliases'] += [new_id, new_id[:12]]
        new['State'].update(Pid=5678, StartedAt='new-fixture-start')
        proof = replacement.validate(frame, new, values[-1]['Config'], old_actual['Id'], created_id=new_id)
        self.assertEqual(proof['pid'], 5678)

    def test_prior_environment_mount_network_and_generation_drift_block(self):
        changes = [lambda a: a['Config']['Env'].append('UNREVIEWED=1'),
                   lambda a: a['Mounts'][0].update(RW=True),
                   lambda a: a['NetworkSettings']['Networks']['fixture-net'].update(MacAddress='06:00:00:00:00:06'),
                   lambda a: a['State'].update(Pid=99)]
        for change in changes:
            with self.subTest(change=change):
                values = fixture();change(values[1]['runtimeBefore']['ingestion'])
                with self.assertRaises(io.Stop):
                    self.build(values)

    def test_new_image_default_or_additional_field_requires_explicit_review(self):
        for key, value in [('Env', ['JAVA_HOME=/unreviewed']), ('UnexpectedField', True), ('User', '0')]:
            values = fixture();values[-1]['Config'][key] = value
            with self.subTest(key=key), self.assertRaises(c.Stop):
                self.build(values)
        values = fixture()
        values[-2]['candidate']['imageConfig']['ArgsEscaped'] = True
        values[-1]['Config']['ArgsEscaped'] = True
        self.assertTrue(self.build(values)['fullPriorIngestionFrameMatched'])
        values[1]['runtimeBefore']['ingestion']['Platform'] = 'windows'
        with self.assertRaises(io.Stop):
            self.build(values)

    def test_empty_image_inspect_fields_preserve_actual_container_stdio(self):
        values = fixture()
        for key in c.INSPECT_BOOLEAN_FIELDS:
            values[-1]['Config'][key] = False
        for key in c.INSPECT_STRING_FIELDS:
            values[-1]['Config'][key] = ''
        values[-1]['Config']['StopTimeout'] = None
        for key in ('AttachStdout', 'AttachStderr'):
            values[1]['runtimeBefore']['ingestion']['Config'][key] = True
            values[-2]['frames']['ingestion']['requestTemplate'][key] = True
        proposal = self.build(values)
        request = proposal['frame']['requestTemplate']
        self.assertIs(request['AttachStdout'], True)
        self.assertIs(request['AttachStderr'], True)
        self.assertEqual(proposal['emptyImageInspectFieldsChecked'], sorted(c.INSPECT_FIELDS))
        self.assertNotIn('OpenStdin', request)  # no candidate-image default merged into container config

    def test_inspect_normalization_rejects_nonempty_wrong_types_and_wrong_profile(self):
        for key in sorted(c.INSPECT_FIELDS):
            bad_values = ([True, 0, None, 'false'] if key in c.INSPECT_BOOLEAN_FIELDS
                          else [1, False, None, 'changed'] if key in c.INSPECT_STRING_FIELDS
                          else [0, False, ''])
            for bad in bad_values:
                for index in (-1, -2):
                    values = fixture()
                    config = values[index]['Config'] if index == -1 else values[index]['candidate']['imageConfig']
                    config[key] = bad
                    with self.subTest(key=key, bad=bad, side=index), self.assertRaises((c.Stop, io.Stop)):
                        self.build(values)
        values = fixture();values[0].pop('imageDefaultCompatibilityProfile')
        with self.assertRaisesRegex(c.Stop, 'RECONCILED_IMAGE_INSPECT_PROFILE_REQUIRED'):
            self.build(values)

    def test_observed_inspect_shape_roundtrips_with_explicit_live_container_stdio(self):
        values = fixture()
        actual = values[1]['runtimeBefore']['ingestion']
        old_request = values[-2]['frames']['ingestion']['requestTemplate']
        for key in c.INSPECT_BOOLEAN_FIELDS - {'NetworkDisabled'}:
            values[-1]['Config'][key] = False
            actual['Config'][key] = old_request[key] = key in ('AttachStdout', 'AttachStderr')
        actual['Config']['Domainname'] = old_request['Domainname'] = ''
        for key in ('Hostname', 'Domainname', 'Image'):
            values[-1]['Config'][key] = ''
        proposal = self.build(values)
        frame = proposal['frame'];request = frame['requestTemplate']
        new_id = 'c' * 64
        new = copy.deepcopy(actual)
        new.update(Id=new_id, Image=values[-1]['Id'])
        new['Config'] = {k: copy.deepcopy(v) for k, v in request.items() if k not in ('HostConfig', 'NetworkingConfig')}
        new['Config']['Hostname'] = new_id[:12]
        new['HostConfig'] = copy.deepcopy(request['HostConfig'])
        new['NetworkSettings']['Networks'] = copy.deepcopy(request['NetworkingConfig']['EndpointsConfig'])
        endpoint = new['NetworkSettings']['Networks']['fixture-net']
        endpoint.update(IPAddress='10.41.0.5', GlobalIPv6Address='')
        endpoint['Aliases'] += [new_id, new_id[:12]]
        new['State'].update(Pid=5678, StartedAt='new-fixture-start')
        self.assertEqual(replacement.validate(frame, new, values[-1]['Config'], actual['Id'],
                                             created_id=new_id)['pid'], 5678)
        for key in c.INSPECT_BOOLEAN_FIELDS - {'NetworkDisabled'}:
            self.assertIs(new['Config'][key], actual['Config'][key])

    def test_only_new_ingestion_operation_no_replay_or_implied_authority(self):
        values = fixture();proposal = self.build(values)
        self.assertEqual(len(proposal['stages']), 12)
        self.assertFalse(proposal['nativeRuntimeExecutorQualified'])
        self.assertFalse(proposal['runtimeAuthorityIssued'])
        self.assertFalse(proposal['sourceActivationAllowed'])
        self.assertTrue(proposal['configuredNormalRuntimeWorkMayResumeOnStart'])
        self.assertEqual(proposal['gatewayWrites'], 0)
        self.assertTrue(all(not s['name'].startswith('gateway.') for s in proposal['stages']))
        for stage in proposal['stages']:
            self.assertEqual(stage['intentHash'], io.digest(stage['intent']))
        changed = fixture();changed[0]['candidateImageId'] = 'different'
        with self.assertRaises(c.Stop):
            self.build(changed)
        changed = fixture();changed[3]['effects'][0]['state'] = 'CLAIMED'
        with self.assertRaises(c.Stop):
            self.build(changed)

    def test_support_byte_tampering_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'input_reader.py').write_text('raise RuntimeError("untrusted code")')
            with self.assertRaisesRegex(c.Stop, 'QUALIFIED_COMPILER_SUPPORT_BYTES_REQUIRED'):
                c.load_support(root)

    def test_private_review_public_summary_and_no_replay(self):
        values = fixture()
        case, snapshot, review, row, packet, candidate = values
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp);case['snapshotRoot'] = str(root)
            completed = {'caseHash': case['inputCaseHash'], 'snapshotHash': io.digest(snapshot),
                         'complete': True, 'runtimeAuthorityIssued': False}
            def read(path, expected=None, root_owned=False):
                name = Path(path).name
                if name == 'snapshot.json': return snapshot, b'snapshot'
                if name == 'complete.json': return completed, b'complete'
                if name == 'review.json': return review, b'review'
                if name == 'recovery.json': return row, b'row'
                if name == 'metadata.json': return snapshot['candidateMetadata'], b'meta'
                if name == 'image-inspect.json': return [candidate], b'inspect'
                return packet, b'packet'
            original = Path.lstat
            def root_owned(path):
                s = original(path)
                return SimpleNamespace(st_uid=0, st_mode=s.st_mode) if path == root else s
            with patch.object(io, 'read_json', read), patch.object(c, 'binding', return_value={'sha256': 'fixture'}), \
                    patch.object(Path, 'lstat', root_owned), \
                    patch('socket.socket', side_effect=AssertionError('unexpected network operation')):
                result = c.run(modules, case)
                self.assertEqual(result['engineRequests'], 0)
                self.assertEqual(result['plannedStages'], 12)
                self.assertNotIn('private-fixture-value', json.dumps(result))
                self.assertNotIn('never-print-this', json.dumps(result))
                self.assertIn('private-fixture-value', (Path(result['contextPath']) / 'review.json').read_text())
                with self.assertRaisesRegex(c.Stop, 'REVIEW_ALREADY_EXISTS_DO_NOT_REPLAY'):
                    c.run(modules, case)

    def test_predecessor_review_or_changed_reconciled_snapshot_blocks_new_review(self):
        case, snapshot, *_ = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp);case['snapshotRoot'] = str(root)
            predecessor = root / ('ingestion-readiness-patch-review-' + case['predecessorReviewCaseHash'])
            predecessor.mkdir()
            (predecessor / 'claim.json').write_text('retained')
            original = Path.lstat
            def owned(path):
                s = original(path)
                return SimpleNamespace(st_uid=0, st_mode=s.st_mode) if path == root else s
            with patch.object(Path, 'lstat', owned), \
                    self.assertRaisesRegex(c.Stop, 'PREDECESSOR_REVIEW_EXISTS_RECONCILE_REQUIRED'):
                c.run(modules, case)
            self.assertEqual((predecessor / 'claim.json').read_text(), 'retained')
        with tempfile.TemporaryDirectory() as tmp:
            case['snapshotRoot'] = tmp
            root = Path(tmp)
            case['reconciledInputSnapshotHash'] = 'changed'
            complete = {'caseHash': case['inputCaseHash'], 'snapshotHash': io.digest(snapshot),
                        'complete': True, 'runtimeAuthorityIssued': False}
            with patch.object(Path, 'lstat', owned), \
                    patch.object(io, 'read_json', side_effect=[(snapshot, b'snapshot'), (complete, b'complete')]):
                with self.assertRaisesRegex(c.Stop, 'EXACT_RECONCILED_INPUT_SNAPSHOT_REQUIRED'):
                    c.run(modules, case)


if __name__ == '__main__':
    unittest.main()
