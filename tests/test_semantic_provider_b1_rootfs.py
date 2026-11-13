"""No real Docker: native custody/CLI/plan plus injected unpack, mount and export.

OUF_B1_ROOTFS_NATIVE=1 requires Linux root and refuses to silently skip.
"""

from contextlib import contextmanager, redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
# Import the pure validator before load_sealer installs its closed tools package.
from tools.semantic_b1_acceptance import acceptance as B
from test_semantic_b1_acceptance import fixture as acceptance_fixture

module_spec = importlib.util.spec_from_file_location('b1_rootfs_controller',
    ROOT / 'scripts/prepare-semantic-provider-b1-rootfs.py')
C = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(C)
REAL_ROOT_MODE = C.expected_root_mode
NATIVE = os.environ.get('OUF_B1_ROOTFS_NATIVE') == '1'
if NATIVE and (sys.platform != 'linux' or os.geteuid() != 0 or os.getegid() != 0
               or not sys.flags.isolated or not sys.dont_write_bytecode):
    raise RuntimeError('OUF_B1_ROOTFS_NATIVE requires Linux root:root and python -I -B')

PINS = {
    'tools/semantic_image_rootfs/prepare_provider_image_rootfs.py':
        'cc2e238c37650f9fa77a2b3319160ef09aa61e1a5bd673e624ad5a9f0106eb32',
    'tools/semantic_stopped_rootfs/stopped_rootfs_comparison.py':
        'fbdf94a8946a2de0504055586a00e25cf6cad0dacd9fa214cc405e49e276e3e5',
    'tools/semantic_stopped_rootfs/rootfs_difference_report.py':
        'cb7b14165da33fcec227f5c9394cb5e640980b4c9be97a6289b9bbc801de8115',
    'tools/semantic_stopped_rootfs/rootfs_image_equivalence.py':
        '5c4fcb28a979ca2d83bcf0bdbbb7d03599170875e30b56de63874891cb79e028'}


class PublicContract(unittest.TestCase):
    def test_historical_library_pins_and_delivery(self):
        launcher = (ROOT / 'scripts/deliver-semantic-provider-b1-rootfs.sh').read_text()
        for path, digest in PINS.items():
            # HEAD bytes, independent of Windows checkout CRLF conversion.
            raw = subprocess.check_output(['git', 'show', 'HEAD:' + path], cwd=ROOT)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
            self.assertIn('fetch ' + path + ' ' + digest, launcher)
        self.assertIn('__PIN_COMMIT__', launcher)
        self.assertIn('__PIN_CONTROLLER_SHA256__', launcher)
        self.assertIn('sudo /usr/bin/python3.13 -I -B', launcher)

    def test_effective_seal_is_exact_and_validated(self):
        actual = {'schema': B.SEAL_SCHEMA, 'sha256': 'a' * 64, 'entries': 2, 'bytes': 4}
        self.assertEqual(C.effective_seal(actual), actual)
        self.assertIsNot(C.effective_seal(actual), actual)
        for delta in ({'schema': 'other'}, {'entries': True}, {'entries': 0},
                      {'bytes': -1}, {'sha256': 'wrong'}, {'extra': 1}):
            with self.subTest(delta=delta), self.assertRaises(C.Denied):
                C.effective_seal({**actual, **delta})


@unittest.skipUnless(NATIVE, 'set OUF_B1_ROOTFS_NATIVE=1 under native Linux sudo')
class NativeController(unittest.TestCase):
    def setUp(self):
        self.old_umask = os.umask(0o077)
        self.addCleanup(os.umask, self.old_umask)
        # /tmp is forbidden by the unchanged libraries' ancestor custody rule.
        self.temp = tempfile.TemporaryDirectory(prefix='ouf-b1-rootfs-test-', dir='/root')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        shutil.copytree(ROOT / 'tools/semantic_cohort_admission/cohort-draft', self.source)
        for path in [self.source, *self.source.rglob('*')]:
            path.chmod(0o700 if path.is_dir() else 0o600)
        self.source_hash = C.sha((self.source / 'sources.json').read_bytes())
        self.cids = {r: str(i) * 64 for i, r in enumerate(C.ROLES, 1)}
        self.images = {r: 'sha256:' + str(i) * 64 for i, r in enumerate(C.ROLES, 3)}
        state = {'Status': 'created', 'Running': False, 'Paused': False, 'Restarting': False,
                 'OOMKilled': False, 'Dead': False, 'Pid': 0, 'ExitCode': 0, 'Error': '',
                 'StartedAt': '0001-01-01T00:00:00Z', 'FinishedAt': '0001-01-01T00:00:00Z'}
        self.documents = {self.cids[r]: {'Id': self.cids[r], 'Image': self.images[r],
            'Name': '/synthetic-' + r, 'State': copy.deepcopy(state),
            'Config': {'MacAddress': '02:00:00:00:00:01', 'Env': ['SYNTHETIC=value']},
            'HostConfig': {'Runtime': 'ouf-semantic-admitted-v2', 'ReadonlyRootfs': r == 'adapter'},
            'Mounts': [], 'NetworkSettings': {'Networks': {'fixture': {'MacAddress': '02:00:00:00:00:01'}}}}
            for r in C.ROLES}
        self.state_file = self.root / 'fake-engine.json'
        self.engine = {'info': {'ServerVersion': '29.8.1', 'Driver': 'overlayfs',
                                'DockerRootDir': str(self.root / 'docker-root')},
                       'version': {'Version': '29.8.1', 'GitCommit': '464cd50'},
                       'documents': self.documents}
        self.save_engine()
        self.binary = self.root / 'fake-docker'
        self.binary.write_text('#!' + sys.executable + '\n' +
            'import json,sys\nfrom pathlib import Path\n' +
            'data=json.loads(Path(' + repr(str(self.state_file)) + ').read_text())\n' +
            'args=sys.argv[5:]\ncommand=args[0]\n' +
            'if command in ("info","version"): print(json.dumps(data[command]))\n' +
            'elif command=="ps": print("\\n".join(data["documents"]))\n' +
            'elif command=="inspect" and args[1]=="--format":\n' +
            ' for cid in args[3:]: print(cid+" "+json.dumps(data["documents"][cid]["State"]))\n' +
            'elif command=="inspect": print(json.dumps([data["documents"][args[1]]]))\n' +
            'else: raise SystemExit("MUTATION_OR_EXPORT_FORBIDDEN_IN_FAKE_DOCKER")\n')
        self.binary.chmod(0o700)
        self.binary_hash = C.sha(self.binary.read_bytes())
        self.a = self.root / 'successors.json'
        self.a_document = {'transaction': 'synthetic', 'containers': [
            {'containerId': self.cids[r], 'image': self.images[r], 'name': '/synthetic-' + r,
             'status': 'created', 'runtime': 'ouf-semantic-admitted-v2', 'dockerFrameSha256': 'f' * 64}
            for r in C.ROLES], 'southboundCertificate': {'liveTlsObserved': False}}
        self.a.write_bytes(C.canonical(self.a_document)); self.a.chmod(0o600)
        self.output = self.root / 'evidence'
        self.cli = []
        def arg(name, value):
            self.cli.extend(['--' + name, str(value)])
        arg('a-successors', self.a); arg('a-successors-sha256', C.sha(self.a.read_bytes()))
        for name in ('umoci', 'docker-init-tool', 'docker', 'mount', 'umount'):
            arg(name, self.binary)
            arg('docker-init-sha256' if name == 'docker-init-tool' else name + '-sha256', self.binary_hash)
        arg('source', self.source); arg('source-manifest-sha256', self.source_hash)
        arg('engine-version', '29.8.1'); arg('engine-commit', C.SUPPORTED_INIT_COMMIT)
        arg('docker-root', self.root / 'docker-root'); arg('docker-socket', 'unix:///var/run/docker.sock')
        arg('output-root', self.root); arg('output-name', 'evidence')
        for r in C.ROLES:
            archive = self.root / (r + '.tar.gz'); archive.write_bytes(b'SYNTHETIC_ARCHIVE:' + r.encode()); archive.chmod(0o600)
            arg(r + '-container-id', self.cids[r]); arg(r + '-image-id', self.images[r])
            arg(r + '-archive', archive); arg(r + '-archive-sha256', C.sha(archive.read_bytes()))
            arg(r + '-config-digest', 'sha256:' + 'd' * 64)
        self.exports = []; self.events = []; self.mutate_after_export = None

    def save_engine(self):
        self.state_file.write_bytes(C.canonical(self.engine)); self.state_file.chmod(0o600)

    def replace(self, flag, value):
        self.cli[self.cli.index('--' + flag) + 1] = str(value)

    def run_controller(self, mode):
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = C.main([*mode, *self.cli])
        return code, json.loads(stream.getvalue())

    def plan(self):
        code, result = self.run_controller(['--plan'])
        self.assertEqual(code, 0, result)
        return result

    def held(self, reason, mode=None):
        code, result = self.run_controller(mode or ['--plan'])
        self.assertEqual(code, 1, result)
        self.assertEqual(result['status'], 'HELD')
        self.assertEqual(result['reason'], reason, result)
        return result

    def tree(self):
        return {str(p.relative_to(self.root)): (p.lstat().st_mode,
                C.sha(p.read_bytes()) if p.is_file() else None) for p in self.root.rglob('*')}

    def test_cli_rejects_missing_malformed_and_duplicate_ids(self):
        bad = [[], ['--apply', *self.cli], ['--plan', '--apply', *self.cli],
               ['--plan', '--plan-sha256', 'a' * 64, *self.cli]]
        for name, value in (('adapter-container-id', 'short'), ('engine-commit', '464cd50'),
                            ('adapter-image-id', 'abc'), ('output-name', '../escape'),
                            ('output-root', '/root/../root'), ('docker-socket', 'tcp://host:2375'),
                            ('source-manifest-sha256', 'Z' * 64),
                            ('southbound-container-id', self.cids['adapter'])):
            argv = ['--plan', *self.cli]; argv[argv.index('--' + name) + 1] = value; bad.append(argv)
        for argv in bad:
            with self.subTest(argv=argv[:3]), redirect_stdout(io.StringIO()), patch('sys.stderr', io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    C.arguments(argv)
                self.assertEqual(caught.exception.code, 2)

    def test_plan_is_stable_read_only_and_has_exact_operations(self):
        before = self.tree()
        with patch.object(C, 'prepare', side_effect=AssertionError('unpack during plan')), \
             patch.object(C, 'stopped_export_view', side_effect=AssertionError('export during plan')), \
             patch.object(C, 'expected_overlay', side_effect=AssertionError('mount during plan')), \
             patch.object(C, 'write_once', side_effect=AssertionError('write during plan')):
            first = self.plan(); second = self.plan()
        self.assertEqual(first, second)
        self.assertEqual(before, self.tree())
        self.assertFalse(self.output.exists())
        self.assertEqual(first['planSha256'], C.sha(C.canonical(first['plan'])))
        self.assertEqual(first['plan']['operations']['stoppedContainerExports'], 2)
        self.assertEqual(first['plan']['operations']['dockerStartRequests'], 0)
        self.assertNotIn('SYNTHETIC=value', json.dumps(first))

    def test_candidate_guards(self):
        for changes in ({'Status': 'exited'}, {'Status': 'running', 'Running': True, 'Pid': 12},
                        {'StartedAt': '2026-11-12T12:00:00Z'}, {'StartedAt': '0001-01-01garbage'},
                        {'Pid': 1}):
            original = copy.deepcopy(self.documents[self.cids['adapter']]['State'])
            self.documents[self.cids['adapter']]['State'].update(changes); self.save_engine()
            self.held('NEVER_STARTED_EXACT_CANDIDATE_REQUIRED')
            self.documents[self.cids['adapter']]['State'] = original
        self.documents[self.cids['adapter']]['Image'] = 'sha256:' + 'f' * 64; self.save_engine()
        self.held('NEVER_STARTED_EXACT_CANDIDATE_REQUIRED')
        self.assertFalse(self.output.exists())

    def test_a_bindings_both_cid_and_image(self):
        for key, value in (('containerId', 'f' * 64), ('image', 'sha256:' + 'f' * 64)):
            original = copy.deepcopy(self.a_document)
            self.a_document['containers'][0][key] = value
            self.a.write_bytes(C.canonical(self.a_document))
            self.replace('a-successors-sha256', C.sha(self.a.read_bytes()))
            self.held('A_SUCCESSOR_BINDING_MISMATCH')
            self.a_document = original
        self.assertFalse(self.output.exists())

    def test_existing_output_and_wrong_binary_hash(self):
        self.output.mkdir(mode=0o700)
        self.held('NEW_OUTPUT_DIRECTORY_REQUIRED')
        self.output.rmdir()
        self.replace('mount-sha256', '0' * 64)
        self.held('UMOCI_BINARY_DRIFT')
        self.assertFalse(self.output.exists())

    def test_archive_custody_hash_and_source_drift(self):
        archive = self.root / 'adapter.tar.gz'
        archive.chmod(0o644); self.held('PRIVATE_FROZEN_IMAGE_REQUIRED'); archive.chmod(0o600)
        archive.write_bytes(b'CHANGED'); self.held('FROZEN_IMAGE_HASH_DRIFT')
        self.replace('adapter-archive-sha256', C.sha(archive.read_bytes()))
        self.replace('source-manifest-sha256', '0' * 64)
        self.held('SEALED_SOURCE_MANIFEST_DRIFT')
        self.assertFalse(self.output.exists())

    def test_engine_guards(self):
        for section, key, value in (('info', 'Driver', 'overlay2'), ('info', 'DockerRootDir', '/other'),
                                    ('info', 'ServerVersion', '29.8.2'), ('version', 'GitCommit', '0000000')):
            old = self.engine[section][key]; self.engine[section][key] = value; self.save_engine()
            self.held('ENGINE_BINDING_DRIFT'); self.engine[section][key] = old

    def test_apply_digest_mismatch_and_changed_candidate_write_nothing(self):
        before = self.tree()
        self.held('PLAN_DIGEST_CHANGED', ['--apply', '--plan-sha256', '0' * 64])
        self.assertEqual(before, self.tree())
        digest = self.plan()['planSha256']
        self.documents[self.cids['adapter']]['Config']['MacAddress'] = None; self.save_engine()
        before = self.tree()
        self.held('PLAN_DIGEST_CHANGED', ['--apply', '--plan-sha256', digest])
        self.assertEqual(before, self.tree()); self.assertFalse(self.output.exists())

    def fake_prepare(self, archive, archive_hash, image, config, umoci, umoci_hash, source, source_hash, output):
        self.events.append('prepare')
        role = output.parent.name
        self.assertEqual(output, self.output / role / 'offline')
        self.assertEqual(image, self.images[role]); self.assertEqual(config, 'sha256:' + 'd' * 64)
        self.assertEqual(archive, self.root / (role + '.tar.gz'))
        self.assertEqual(archive_hash, C.sha(archive.read_bytes()))
        self.assertEqual((umoci, umoci_hash), (self.binary, self.binary_hash))
        self.assertEqual((source, source_hash), (self.source, self.source_hash))
        self.assertFalse(list(output.iterdir()))
        (output / 'bundle').mkdir(mode=0o700); lower = output / 'bundle/rootfs'; lower.mkdir(mode=0o700)
        (lower / 'payload').write_bytes(b'fixture'); (lower / 'payload').chmod(0o600)
        (output / 'layout').mkdir(mode=0o700)
        # Real layer policy reader, using an authenticated synthetic manifest/layer.
        import tarfile
        layer = output / 'layer.tar'
        with tarfile.open(layer, 'w') as stream:
            entry = tarfile.TarInfo('.'); entry.type = tarfile.DIRTYPE; entry.mode = 0o755; stream.addfile(entry)
        layer_bytes = layer.read_bytes(); layer.unlink()
        blobs = output / 'layout/blobs'; blobs.mkdir(mode=0o700); (blobs / 'sha256').mkdir(mode=0o700)
        layer_digest = 'sha256:' + C.sha(layer_bytes)
        C.write_once(blobs / 'sha256' / layer_digest[7:], layer_bytes)
        manifest = C.canonical({'layers': [{'digest': layer_digest}]})
        manifest_digest = 'sha256:' + C.sha(manifest)
        C.write_once(blobs / 'sha256' / manifest_digest[7:], manifest)
        self.layer_policy = REAL_ROOT_MODE(output / 'layout', manifest_digest)
        limits = {'maxEntries': 100, 'maxBytes': 1024, 'maxDepth': 8}
        seal = C.load_sealer(source, source_hash)(lower, limits, C.Budget())
        receipt = {'schema': 'ouf.semantic-offline-image-rootfs.v1', 'archiveSha256': archive_hash,
                   'manifestDigest': image, 'configDigest': config, 'sourceManifestSha256': source_hash,
                   'rootfsSeal': seal, 'rootfsLimits': limits, 'targetRootfsCompared': False}
        C.write_once(output / 'expected-rootfs.json', C.canonical(receipt))
        return receipt

    def fake_init(self, output, init, init_hash, commit, source, source_hash):
        self.events.append('init')
        self.assertEqual((init, init_hash), (self.binary, self.binary_hash))
        self.assertEqual(commit, C.SUPPORTED_INIT_COMMIT)
        self.assertEqual((source, source_hash), (self.source, self.source_hash))
        receipt = C.decode(C.private(output / 'expected-rootfs.json'))
        receipt = {**receipt, 'schema': 'ouf.semantic-offline-docker-rootfs.v1', 'engineCommit': commit,
                   'offlineDockerInitLayerApplied': True}
        C.write_once(output / 'docker-init-claim.json', b'{}')
        C.write_once(output / 'expected-docker-rootfs.json', C.canonical(receipt))
        return receipt

    @contextmanager
    def fake_overlay(self, lower, directory, mount, umount):
        self.events.append('mount')
        self.assertEqual(mount, (self.binary, self.binary_hash)); self.assertEqual(umount, mount)
        self.assertFalse(list(directory.iterdir()))
        yield lower
        self.events.append('unmount')

    @contextmanager
    def fake_export(self, binding, socket, config, cid, target):
        self.assertEqual(binding, (self.binary, self.binary_hash))
        self.assertEqual(target, self.root / 'docker-root/rootfs/overlayfs' / cid)
        self.assertEqual(config, self.output / 'docker-config')
        self.assertTrue(config.is_dir())
        self.exports.append(cid); self.events.append('export')
        role = next(r for r in C.ROLES if self.cids[r] == cid)
        yield self.actual / role
        if self.mutate_after_export:
            self.mutate_after_export(role)
        self.events.append('release-export')

    def injected_apply(self, different=False):
        self.actual = self.root / 'actual'; self.actual.mkdir(mode=0o700)
        for role in C.ROLES:
            directory = self.actual / role; directory.mkdir(mode=0o755); directory.chmod(0o755)
            (directory / 'payload').write_bytes(b'different' if different else b'fixture')
            (directory / 'payload').chmod(0o600)
        digest = self.plan()['planSha256']
        # Keep real sealer, entry capture, classifier, image equivalence, plan,
        # custody, write_once and result building; inject only privileged effects.
        with patch.object(C, 'prepare', side_effect=self.fake_prepare), \
             patch.object(C, 'apply_docker_init', side_effect=self.fake_init), \
             patch.object(C, 'expected_overlay', side_effect=self.fake_overlay), \
             patch.object(C, 'stopped_export_view', side_effect=self.fake_export), \
             patch.object(C, 'expected_root_mode', side_effect=lambda *args: self.layer_policy):
            return self.run_controller(['--apply', '--plan-sha256', digest])

    def test_apply_uses_actual_seal_and_builds_task15_manifest(self):
        code, result = self.injected_apply()
        self.assertEqual(code, 0, result)
        self.assertEqual(self.exports, list(self.cids.values()))
        self.assertEqual(self.events.count('prepare'), 2); self.assertEqual(self.events.count('init'), 2)
        self.assertEqual(self.events.count('export'), 2); self.assertEqual(self.events.count('release-export'), 2)
        self.assertEqual(self.events.count('mount'), 2); self.assertEqual(self.events.count('unmount'), 2)
        manifest = acceptance_fixture()
        for role, produced in result['roles'].items():
            manifest['roles'][role]['containerId'] = produced['containerId']
            manifest['roles'][role]['imageId'] = produced['imageId']
            manifest['roles'][role]['rootfs'] = {key: produced[key] for key in
                ('offlineImageReceipt', 'offlineDockerReceipt', 'comparison', 'effectiveSeal')}
            for key in ('offlineImageReceipt', 'offlineDockerReceipt', 'comparison'):
                binding = produced[key]
                self.assertEqual(C.sha(C.private(Path(binding['path']))), binding['sha256'])
            record = C.decode(C.private(Path(produced['comparison']['path'])))
            self.assertFalse(record['strictSealsMatch'])
            self.assertTrue(record['imageEquivalence']['equivalent'])
            self.assertEqual(produced['effectiveSeal'], record['actualSeal'])
        self.assertEqual(B.decode_manifest(B.build_acceptance(**manifest)), manifest)
        self.assertEqual(result, C.decode(C.private(self.output / 'result.json')))
        for path in (self.output, self.output / 'adapter', self.output / 'adapter/offline'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.output / 'result.json').stat().st_mode & 0o777, 0o600)
        self.assertFalse(result['acceptanceGranted']); self.assertFalse(result['startAuthorized'])
        self.assertEqual(result['containerLifecycleOperations'], 0); self.assertEqual(result['dockerStartRequests'], 0)
        self.assertEqual(result['stoppedContainerExports'], 2)
        self.held('NEW_OUTPUT_DIRECTORY_REQUIRED', ['--apply', '--plan-sha256', result['planSha256']])

    def test_difference_retains_comparison_but_never_success(self):
        code, result = self.injected_apply(different=True)
        self.assertEqual(code, 1, result)
        self.assertEqual(result['reason'], 'TARGET_ROOTFS_DIFFERS_FROM_INDEPENDENT_EXPECTATION')
        comparison = self.output / 'adapter-comparison.json'
        self.assertTrue(comparison.exists()); self.assertIn(str(comparison), result['writtenFiles'])
        record = C.decode(C.private(comparison))
        self.assertGreater(record['differences']['differentEntryCount'], 0)
        self.assertFalse(record['imageEquivalence']['equivalent'])
        self.assertFalse((self.output / 'result.json').exists()); self.assertEqual(len(self.exports), 1)
        self.assertEqual(result['phase'], 'adapter:COMPARE'); self.assertTrue(result['outputCreated'])

    def test_configuration_change_including_mac_is_never_normalized(self):
        def mutate(role):
            self.documents[self.cids[role]]['Config'].pop('MacAddress'); self.save_engine()
        self.mutate_after_export = mutate
        code, result = self.injected_apply()
        self.assertEqual(code, 1, result)
        self.assertEqual(result['reason'], 'STOPPED_CANDIDATE_CONFIGURATION_CHANGED')
        self.assertFalse((self.output / 'result.json').exists())

    def test_any_container_lifecycle_change_blocks_success(self):
        def mutate(role):
            self.documents[self.cids['southbound']]['State']['ExitCode'] = 1; self.save_engine()
        self.mutate_after_export = mutate
        code, result = self.injected_apply()
        self.assertEqual(code, 1, result)
        self.assertEqual(result['reason'], 'EXISTING_CONTAINER_STATES_CHANGED')
        self.assertFalse((self.output / 'result.json').exists())


if __name__ == '__main__':
    unittest.main()
