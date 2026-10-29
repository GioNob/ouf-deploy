"""Actual POSIX source custody and private publication, synthetic source bytes."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('retained_expectations', ROOT / 'scripts/prepare-retained-v11-source-expectations.py')
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)
atomic_raw = (ROOT / 'tools/semantic_application_cutover/atomic_review_intake.py').read_bytes()


class Expectations(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.directory = self.root / 'retained-directory'
        self.directory.mkdir(mode=0o750)
        if os.environ.get('OUF_NATIVE_UIDS') == '1':
            os.chown(self.directory, 0, 10001)
        self.member = self.directory / 'legacy.private'
        self.member.write_bytes(b'SYNTHETIC_PRIVATE_BYTES_DO_NOT_PRINT')
        if os.environ.get('OUF_NATIVE_UIDS') == '1':
            os.chown(self.member, 0, 10001)
        self.member.chmod(0o640)
        self.file = self.root / 'retained-file'
        self.file.write_bytes(b'SYNTHETIC_RETAINED_KEY_DO_NOT_PRINT')
        if os.environ.get('OUF_NATIVE_UIDS') == '1':
            os.chown(self.file, 10001, 10001)
        self.file.chmod(0o400)

    def binding(self, source, target='/retained'):
        return {'Type': 'bind', 'Source': str(source), 'Destination': target, 'RW': False}

    def metadata(self, source):
        rows = [planner.metadata(source.lstat(), '')]
        if source.is_dir():
            rows += [planner.metadata(member.lstat(), member.name) for member in sorted(source.iterdir())]
        return rows

    def test_exact_directory_member_and_file_hash_without_byte_output(self):
        for source in (self.directory, self.file):
            result, total = planner.source_scope(self.binding(source), self.metadata(source))
            file = self.member if source == self.directory else self.file
            self.assertEqual(result['sha256'], hashlib.sha256(file.read_bytes()).hexdigest())
            self.assertEqual(total, file.stat().st_size * 2)
            self.assertNotIn('SYNTHETIC_PRIVATE_BYTES', json.dumps(result))
            self.assertNotIn('SYNTHETIC_RETAINED_KEY', json.dumps(result))
        result, _ = planner.source_scope(self.binding(self.directory), self.metadata(self.directory))
        self.assertEqual((result['fileUid'], result['fileGid'], result['fileMode']),
                         (self.member.stat().st_uid, self.member.stat().st_gid, 0o640))

    def test_stale_metadata_extra_member_and_link_scopes_denied_before_read(self):
        expected = self.metadata(self.directory)
        self.member.chmod(0o600)
        with patch.object(planner.os, 'read', side_effect=AssertionError('SOURCE_BYTES_READ')):
            with self.assertRaisesRegex(ValueError, 'MEMBER_METADATA_DRIFT'):
                planner.source_scope(self.binding(self.directory), expected)
            extra = self.directory / 'foreign'
            extra.write_bytes(b'foreign')
            with self.assertRaisesRegex(ValueError, 'BOUNDED_RETAINED_METADATA'):
                planner.source_scope(self.binding(self.directory), self.metadata(self.directory))
            link = self.root / 'link'
            link.symlink_to(self.file)
            with self.assertRaises(OSError):
                planner.source_scope(self.binding(link), self.metadata(self.file))

    def test_no_follow_ancestor_and_hardlink_or_oversized_file_denied(self):
        ancestor = self.root / 'linked-parent'
        ancestor.symlink_to(self.directory)
        with self.assertRaises(OSError):
            planner.source_scope(self.binding(ancestor / self.member.name), self.metadata(self.member))
        linked = self.root / 'hardlink'
        os.link(self.file, linked)
        with self.assertRaisesRegex(ValueError, 'SINGLE_LINK'):
            planner.source_scope(self.binding(self.file), self.metadata(self.file))
        linked.unlink()
        self.file.chmod(0o600)
        self.file.write_bytes(b'x' * (planner.MAX_BYTES + 1))
        with self.assertRaisesRegex(ValueError, 'SINGLE_LINK'):
            planner.source_scope(self.binding(self.file), self.metadata(self.file))

    def test_mid_read_change_is_blocked_and_partial_read_count_remains_visible(self):
        expected = self.metadata(self.file)
        read = planner.os.read
        calls = []
        def changed(fd, amount):
            raw = read(fd, amount)
            if raw and not calls:
                calls.append(True)
                self.file.chmod(0o600)
                self.file.write_bytes(b'changed')
            return raw
        counted = []
        with patch.object(planner.os, 'read', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'CHANGED_DURING_HASH'):
                planner.source_scope(self.binding(self.file), expected, counted.append)
        self.assertGreater(sum(counted), 0)

    def fixture(self, mixed=False):
        base = self.root / 'snapshots'
        base.mkdir(mode=0o700)
        parent = base / 'parent'
        parent.mkdir(mode=0o700)
        entries = [{'binding': self.binding(source, '/retained-' + str(index)),
                    'sourceMetadata': self.metadata(source)}
                   for index, source in enumerate((self.directory, self.file))]
        binds = [str(self.root / ('SYNTHETIC_PRIVATE_BIND_DO_NOT_PRINT-' + str(i)))
                 + ':/synthetic-' + str(i) + ':ro' for i in range(6)]
        host = {'Binds': binds}
        if mixed:
            host = {'Binds': binds[2:], 'Mounts': [
                {'Type': 'bind', 'Source': entry['binding']['Source'],
                 'Target': entry['binding']['Destination'], 'ReadOnly': True,
                 'BindOptions': {'Propagation': 'rprivate'}} for entry in entries]}
        request = {'HostConfig': host,
                   'Env': ['PRIVATE_FIXTURE=DO_NOT_PRINT_ENV']}
        files = dict(zip(planner.NAMES, map(planner.encoded, (request, {}, entries, {}))))
        manifest = {'schema': 'ouf.native-v11-atomic-review-intake.v1',
                    'purpose': 'GATED_REQUEST_AND_FULL_RETAINED_MOUNT_METADATA_ONLY',
                    'fileHashes': {name: planner.sha(raw) for name, raw in files.items()},
                    'applicationCutoverAuthorized': False, 'productionApplyReady': False,
                    'runtimeAuthorityIssued': False}
        raw_manifest = planner.encoded(manifest)
        for name, raw in {**files, 'intake.json': raw_manifest}.items():
            path = parent / name
            path.write_bytes(raw)
            path.chmod(0o600)
        scoped = types.SimpleNamespace(flags=types.SimpleNamespace(isolated=1),
                                       dont_write_bytecode=True, argv=['fixture'])
        bindings = {'BASE': base, 'PARENT': parent, 'PARENT_HASH': planner.sha(raw_manifest),
                    'REQUEST_HASH': planner.sha(files[planner.NAMES[0]]),
                    'METADATA_HASHES': tuple(planner.sha(planner.encoded(row['sourceMetadata'])) for row in entries),
                    'sys': scoped}
        return bindings, files

    def run_entry(self, bindings):
        output = io.StringIO()
        with patch.multiple(planner, **bindings), patch.dict(planner.__dict__, {
                '__atomic_source__': atomic_raw, '__sealed_program_sha__': 'f' * 64}), \
                contextlib.redirect_stdout(output):
            code = planner.main()
        text = output.getvalue()
        return code, json.loads(text.split('=', 1)[1]), text

    def test_private_atomic_publication_is_repeatable_and_output_has_no_secrets(self):
        bindings, originals = self.fixture()
        code, report, output = self.run_entry(bindings)
        self.assertEqual(code, 0)
        self.assertEqual(report['protectedFileWrites'], 3)
        self.assertTrue(report['publicationIsAtomic'])
        self.assertFalse(report['completeSixMountClosureProven'])
        self.assertFalse(report['runtimeAuthorityIssued'])
        self.assertEqual(report['retainedSources'][0]['fileMode'], 0o640)
        for secret in ('SYNTHETIC_PRIVATE', 'SYNTHETIC_RETAINED', 'DO_NOT_PRINT_ENV', str(self.directory)):
            self.assertNotIn(secret, output)
        expected = (Path(report['directory']) / 'retained-source-expectations.private.json').read_bytes()
        self.assertNotIn('SYNTHETIC_PRIVATE_BYTES', expected.decode())
        self.assertEqual(report['mountedSourceContentBytesHashed'],
                         4 * (self.member.stat().st_size + self.file.stat().st_size))
        for path in Path(report['directory']).iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for name, raw in originals.items():
            self.assertEqual((bindings['PARENT'] / name).read_bytes(), raw)
        code, again, _ = self.run_entry(bindings)
        self.assertEqual(code, 0)
        self.assertEqual(again['intakeHash'], report['intakeHash'])
        self.assertEqual(again['protectedFileWrites'], 0)

    def test_four_binds_and_two_retained_structured_mounts_complete_private_preparation(self):
        bindings, originals = self.fixture(mixed=True)
        code, report, output = self.run_entry(bindings)
        self.assertEqual(code, 0)
        self.assertEqual(report['protectedFileWrites'], 3)
        self.assertEqual(report['requestMountShape'], {
            'bindCount': 4, 'structuredMountCount': 2, 'totalMountCount': 6,
            'sealedRequestRewritten': False})
        self.assertNotIn('DO_NOT_PRINT', output)
        for name, raw in originals.items():
            self.assertEqual((bindings['PARENT'] / name).read_bytes(), raw)

    def test_combined_mount_shape_denies_missing_extra_writable_and_shadowed_declarations(self):
        bindings, _ = self.fixture(mixed=True)
        request = json.loads((bindings['PARENT'] / planner.NAMES[0]).read_bytes())
        import copy
        variants = []
        missing = copy.deepcopy(request); missing['HostConfig']['Mounts'].pop(); variants.append(missing)
        extra = copy.deepcopy(request); extra['HostConfig']['Binds'].append('/x:/extra:ro'); variants.append(extra)
        writable = copy.deepcopy(request); writable['HostConfig']['Mounts'][0]['ReadOnly'] = False; variants.append(writable)
        duplicate = copy.deepcopy(request); duplicate['HostConfig']['Mounts'][0]['Target'] = '/synthetic-2'; variants.append(duplicate)
        shadow = copy.deepcopy(request); shadow['HostConfig']['Mounts'][0]['Target'] = '/synthetic-2/child'; variants.append(shadow)
        malformed = copy.deepcopy(request); malformed['HostConfig']['Mounts'] = {}; variants.append(malformed)
        for value in variants:
            with self.subTest(value=value):
                with self.assertRaises(planner.Denied):
                    planner.request_mount_shape(value)

    def test_parent_drift_and_unknown_errors_have_no_writes_or_private_error_text(self):
        bindings, _ = self.fixture()
        path = bindings['PARENT'] / planner.NAMES[0]
        path.write_bytes(path.read_bytes() + b' ')
        code, report, _ = self.run_entry(bindings)
        self.assertEqual(code, 1)
        self.assertEqual(report['reason'], 'GATED_PARENT_FILE_HASH_DRIFT')
        self.assertEqual(report['protectedFileWrites'], 0)
        with patch.object(planner, 'source_scope', side_effect=RuntimeError('SECRET_RUNTIME_TEXT')):
            path.write_bytes(path.read_bytes()[:-1])
            code, report, text = self.run_entry(bindings)
        self.assertEqual(code, 1)
        self.assertEqual(report['reason'], 'RETAINED_SOURCE_EXPECTATIONS_UNPROVEN')
        self.assertNotIn('SECRET_RUNTIME_TEXT', text)

    def test_atomic_source_is_pinned_before_execution_and_json_duplicates_denied(self):
        with self.assertRaisesRegex(ValueError, 'SEALED_ATOMIC'):
            planner.atomic_source(atomic_raw + b'\n')
        with self.assertRaisesRegex(ValueError, 'DUPLICATE'):
            planner.decode(b'{"same": 1, "same": 2}')

    def test_private_parent_symlink_is_denied_and_original_parent_preserved(self):
        bindings, originals = self.fixture()
        linked = bindings['BASE'] / 'linked-parent'
        linked.symlink_to(bindings['PARENT'])
        code, report, _ = self.run_entry({**bindings, 'PARENT': linked})
        self.assertEqual(code, 1)
        self.assertEqual(report['reason'], 'ROOT_PROTECTED_REVIEW_ANCESTOR_REQUIRED')
        self.assertEqual(report['mountedSourceContentBytesHashed'], 0)
        self.assertEqual(report['protectedFileWrites'], 0)
        for name, raw in originals.items():
            self.assertEqual((bindings['PARENT'] / name).read_bytes(), raw)

    def test_interrupted_private_publication_requires_reconciliation_not_success(self):
        bindings, _ = self.fixture()
        atomic = planner.atomic_source(atomic_raw)
        original = atomic.publish
        def interrupted(base, files, manifest, uid, checkpoint):
            def fail(point):
                checkpoint(point)
                if point == 'BEFORE_ATOMIC_PUBLICATION':
                    raise RuntimeError('PRIVATE_FAILURE_TEXT')
            return original(base, files, manifest, uid, fail)
        atomic.publish = interrupted
        with patch.object(planner, 'atomic_source', return_value=atomic):
            code, report, text = self.run_entry(bindings)
        self.assertEqual(code, 1)
        self.assertEqual(report['protectedFileWrites'], 3)
        self.assertTrue(report['privateWriteOutcomeRequiresReconciliation'])
        self.assertNotIn('PRIVATE_FAILURE_TEXT', text)
        self.assertNotIn('publicationIsAtomic', report)
        self.assertEqual(len(list(bindings['BASE'].glob('.semantic-native-v11-intake-staging-*'))), 1)


if __name__ == '__main__':
    unittest.main()
