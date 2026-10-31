"""Read-only retained-stop probe: exact capsule, no entry, bounded public output."""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / 'scripts/read-registry-postboot-stop-20261023.py'
spec = importlib.util.spec_from_file_location('retained_stop_probe_fixture', SCRIPT)
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
CAPSULE = ROOT / 'releases/semantic-registry-postboot-20261023.py'
WRAPPER = ROOT / 'releases/semantic-registry-postboot-stop-read-20261023.sh'


class RetainedStopRead(unittest.TestCase):
    def test_exact_published_capsule_decodes_without_running_bootstrap_or_entry(self):
        case, manifest, loader, sources = p.unpack(CAPSULE.read_bytes())
        self.assertEqual(p.digest(manifest), p.CLOSURE_HASH)
        self.assertEqual(len(sources), 105)
        self.assertEqual(case['schema'], 'ouf.semantic-registry-postboot-recovery-case.v1')
        self.assertIn(b'def load_entry(', loader)

    def test_changed_capsule_rejected_before_parsing_or_preload(self):
        for raw in (b'raise RuntimeError("PRIVATE_VALUE")', CAPSULE.read_bytes() + b'\n'):
            with self.assertRaisesRegex(p.Stop, 'EXACT_FAILED_CAPSULE_HASH_REQUIRED'):
                p.unpack(raw)

    def test_actual_isolated_full_preload_never_calls_entry(self):
        program = ('ns={"__name__":"probe_fixture"}\nexec(' + repr(SCRIPT.read_bytes()) + ',ns)\n'
            'from pathlib import Path\ncase,manifest,loader,sources=ns["unpack"](Path('
            + repr(str(CAPSULE)) + ').read_bytes())\n'
            'Files=ns["preload"](manifest,loader,sources)\n'
            'assert Files.__name__=="Files"\n'
            'import sys\nentry=sys.modules["tools.semantic_registry_recovery_execution.postboot_entry"]\n'
            'assert callable(entry.execute)\nprint("READ_ONLY_PRELOAD_FINISHED_NO_ENTRY")\n')
        result = subprocess.run([sys.executable, '-I', '-B', '-S', '-'], input=program.encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, cwd='/')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b'')
        self.assertEqual(result.stdout.strip(), b'READ_ONLY_PRELOAD_FINISHED_NO_ENTRY')

    def test_exception_messages_private_filenames_and_locals_are_never_projected(self):
        secret = 'PRIVATE_BEARER_DO_NOT_PRINT'
        try:
            exec(compile('raise KeyError(' + repr(secret) + ')', '/private/' + secret, 'exec'), {})
        except Exception as error:
            value = p.safe_error(error, {})
        text = json.dumps(value)
        self.assertNotIn(secret, text)
        self.assertNotIn('/private', text)
        self.assertEqual(value, [{'exceptionClass': 'KeyError', 'sealedFrames': []}])

    def test_sealed_frame_line_is_reported_without_exception_argument(self):
        name = 'tools.semantic_registry_recovery_execution.postboot_prepare'
        try:
            exec(compile('raise TypeError("PRIVATE_CONTENT")', '<sealed-registry-postboot:' + name + '>', 'exec'), {})
        except Exception as error:
            value = p.safe_error(error, {name: b''})
        self.assertEqual(value[0]['sealedFrames'], [{'module': name, 'line': 1}])
        self.assertNotIn('PRIVATE_CONTENT', json.dumps(value))

    def test_oserror_errno_excludes_path_and_message(self):
        value = p.safe_error(FileNotFoundError(2, 'PRIVATE_MESSAGE', '/private/credential'), {})
        self.assertEqual(value, [{'exceptionClass': 'FileNotFoundError', 'sealedFrames': [], 'errno': 2}])

    def test_marker_inventory_reads_no_contents_and_creates_no_missing_root(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            self.assertFalse(p.markers(root / 'absent')['preparationDirectoryPresent'])
            self.assertFalse((root / 'absent').exists())
            for name in ('claim.json', 'engine-get-1.json', 'engine-get-2.json', 'admin-get.json'):
                (root / name).write_text('PRIVATE_VALUE_NOT_JSON')
                (root / name).chmod(0o400)
            before = {path.name: path.stat().st_mtime_ns for path in root.iterdir()}
            value = p.markers(root)
            self.assertEqual(value['engineAttemptMarkers'], [1, 2])
            self.assertTrue(value['claimPresent']); self.assertTrue(value['adminAttemptMarkerPresent'])
            self.assertFalse(value['frozenGetAttemptMarkerPresent'])
            self.assertEqual(value['markerMeaning'], 'ATTEMPT_NOT_COMPLETION')
            self.assertNotIn('PRIVATE_VALUE', json.dumps(value))
            self.assertEqual(before, {path.name: path.stat().st_mtime_ns for path in root.iterdir()})

    def test_symlink_marker_is_refused_without_following(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory); (root / 'claim.json').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(p.Stop, 'PROTECTED_RETAINED_MARKER_REQUIRED'):
                p.markers(root)

    def test_read_capsule_rejects_symlink_and_does_not_rewrite_file(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / 'capsule.py'; path.write_bytes(CAPSULE.read_bytes())
            self.assertEqual(p.read_capsule(str(path)), CAPSULE.read_bytes())
            link = Path(directory) / 'link'; link.symlink_to(path)
            with self.assertRaises(OSError):
                p.read_capsule(str(link))

    def test_no_direct_runtime_or_write_dispatch_exists_in_probe(self):
        tree = ast.parse(SCRIPT.read_bytes())
        denied = {'execute', 'prepare', '_prepare', 'review', 'issue', 'bootstrap_gate',
                  'continue_recovery', 'mkdir', 'unlink', 'remove', 'rename', 'replace',
                  'system', 'popen', 'request', 'write', 'write_bytes', 'write_text'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, denied)
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'os':
                self.assertNotIn(node.attr, {'O_WRONLY', 'O_RDWR', 'O_CREAT', 'O_TRUNC', 'O_EXCL'})

    def test_metadata_checks_read_only_six_exact_hash_bound_files_and_project_no_values(self):
        case, _, _, _ = p.unpack(CAPSULE.read_bytes()); case = case['preparation']
        bundle_path = p.PARENT + '/fixture-bundle.json'
        bundle_hash = case['lineageReceipt']['historicalBundleHash']
        patch = case['patchContext']; sha = 'a' * 64
        values = {
            case['retainedInputs']['path']: {'registryInputs': {}, 'candidateContract': {}, 'proposal': {
                'registry': {'containerId': 'PRIVATE_ID'}, 'gatewayBinding': {'containerId': 'PRIVATE_ID'},
                'engineBinding': {}, 'retainedPatchReviewHash': sha, 'retainedPatchJournalHash': sha}},
            case['historicalReview']['path']: {'scopes': {'finiteActionProcess': {'bundle': {
                'path': bundle_path, 'sha256': bundle_hash}}}, 'privateInputHashes': {'preparedInputs': sha}},
            bundle_path: {'prepared': {'registry': {}, 'owner': {'hostInputBinding': {}, 'binding': {}}}},
            patch + '/review.json': {'executionReview': {'gatewayTransportProfile': {},
                'databaseControlProfile': {'dockerExecutable': {}},
                'packetBinding': {'path': patch + '/packet.json', 'sha256': sha}}},
            patch + '/recovery.json': {'effects': [
                {'stage': stage, 'nativeResource': {'containerId': 'PRIVATE_ID'}}
                for stage in ('ingestion.CREATE_REPLACEMENT', 'ingestion.START_REPLACEMENT')]},
            patch + '/packet.json': {'retainedGatewayConfig': {'private': 'PRIVATE_VALUE'}}}
        calls = []
        class Files:
            def json(self, path, expected, maximum):
                calls.append((path, expected, maximum))
                return copy.deepcopy(values[path]), {'metadata': [0] * 6 + [100]}
        output = p.base(); p.metadata_shapes(case, Files(), output)
        self.assertEqual(len(calls), 6)
        self.assertEqual(output['metadataReadOperations'], 6)
        self.assertEqual(output['metadataBytesRead'], 600)
        self.assertTrue(all(row['present'] for row in output['retainedShapeChecks']))
        self.assertNotIn('PRIVATE_', json.dumps(output)); self.assertNotIn(bundle_path, json.dumps(output))
        del values[case['retainedInputs']['path']]['registryInputs']
        output = p.base(); p.metadata_shapes(case, Files(), output)
        self.assertIn({'id': 'INPUT_REGISTRY', 'present': False, 'missingAt': 0}, output['retainedShapeChecks'])

    def wrapper_fixture(self, home, content):
        binary = home / 'bin'; binary.mkdir()
        gh = binary / 'gh'
        gh.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$HOME/gh.calls"\ncat "$HOME/source.py"\n')
        sudo = binary / 'sudo'
        sudo.write_text('#!/bin/sh\ntest "$1" = -- || exit 9\nshift\nexec "$@"\n')
        gh.chmod(0o700); sudo.chmod(0o700)
        (home / 'source.py').write_bytes(content)
        return {**os.environ, 'HOME': str(home), 'PATH': str(binary) + ':/usr/bin:/bin'}

    def test_real_wrapper_executes_only_verified_reader_and_retains_safe_stop(self):
        self.assertFalse(Path(p.CAPSULE).exists(), 'disposable fixture must not run on the target')
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            home = Path(directory); environment = self.wrapper_fixture(home, SCRIPT.read_bytes())
            result = subprocess.run(['bash', str(WRAPPER)], env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(result.returncode, 2)
            rows = [json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith('{')]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['diagnosticStage'], 'RETAINED_CAPSULE_VERIFICATION')
            self.assertFalse(rows[0]['applicationEntryInvoked'])
            self.assertEqual(rows[0]['runtimeEffectsDispatched'], 0)
            self.assertIn('errno', rows[0]['safeExceptionChain'][0])
            calls = (home / 'gh.calls').read_text().splitlines()
            self.assertEqual(len(calls), 1)
            self.assertIn('ref=1c94a004139e42b573337d1da71ad6461fe48909', calls[0])
            self.assertIn('--hostname github.com', calls[0])
            retained = list(home.glob('ouf-postboot-stop-read.*'))
            self.assertEqual(len(retained), 1)
            self.assertEqual((retained[0] / 'read.stderr').read_bytes(), b'')

    def test_wrapper_hash_mismatch_prevents_unreviewed_code_execution(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            home = Path(directory)
            environment = self.wrapper_fixture(home, b'raise RuntimeError("PRIVATE_UNREVIEWED_EXECUTED")\n')
            result = subprocess.run(['bash', str(WRAPPER)], env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'EXACT_STOP_READER_ROOT_LAUNCH_UNPROVEN', result.stdout)
            self.assertNotIn(b'PRIVATE_UNREVIEWED_EXECUTED', result.stdout + result.stderr)
            retained = next(home.glob('ouf-postboot-stop-read.*'))
            self.assertEqual((retained / 'read.stderr').read_bytes(), b'')

    def test_wrapper_rejects_arguments_before_any_download(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            home = Path(directory); environment = self.wrapper_fixture(home, SCRIPT.read_bytes())
            result = subprocess.run(['bash', str(WRAPPER), 'prepare'], env=environment,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(result.returncode, 2)
            self.assertFalse((home / 'gh.calls').exists())


if __name__ == '__main__':
    unittest.main()
