"""Actual closed memory imports; no IAM call, worker start, or target mutation."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LOADER = ROOT / 'tools/semantic_policy_token_owner/sealed_runtime.py'
spec = importlib.util.spec_from_file_location('qualified_sealed_runtime', LOADER)
sealed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sealed)

def source_paths():
    paths = {}
    for path in (ROOT / 'tools').rglob('*.py'):
        if 'cohort-draft' in str(path):
            name = 'tools.' + path.stem
        elif path.parent.name == 'semantic_application_cutover':
            name = path.stem
        else:
            name = '.'.join(path.with_suffix('').relative_to(ROOT).parts)
        paths[name] = path
    return {name: paths[name] for name in sealed.MODULES}

class SealedRuntimeTest(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        directory.chmod(0o700)
        sources = {name: path.read_bytes() for name, path in source_paths().items()}
        loader = LOADER.read_bytes()
        manifest = sealed.declaration('a' * 40, sources, loader)
        for name, raw in {'closure.json': sealed.encoded(manifest), 'sealed-runtime.py': loader,
                          **{sealed.filename(n): raw for n, raw in sources.items()}}.items():
            path = directory / name
            path.write_bytes(raw)
            path.chmod(0o600)
        return directory, manifest, sources, loader

    def child(self, directory, manifest, *, after='', prelude='', tail=''):
        code = '''import importlib.util,pathlib,sys,json
spec=importlib.util.spec_from_file_location('bootstrap_sealed',sys.argv[1])
sealed=importlib.util.module_from_spec(spec);spec.loader.exec_module(sealed)
''' + prelude + '''
runtime=sealed.verify_bundle(sys.argv[2],sys.argv[3],pathlib.Path(sys.argv[1]).read_bytes())
''' + after + '''
entry=runtime.load_entry()
assert callable(entry.build_worker) and callable(entry.run)
assert entry.InstalledTokenOwner.__module__=='tools.semantic_policy_token_owner.installed_owner'
assert 'cutover_authority' in sys.modules
assert sys.modules['tools'].__path__==[]
''' + tail + '''
print(json.dumps({'memoryImportPassed':True,'closureHash':runtime.manifest_hash,'providerCalls':0}))
'''
        return subprocess.run([sys.executable, '-I', '-B', '-c', code, str(LOADER), str(directory),
                               sealed.digest(manifest)], capture_output=True, timeout=20)

    def test_complete_actual_worker_and_authority_dependencies_load_without_path(self):
        directory, manifest, sources, loader = self.fixture()
        self.assertEqual(len(sources), 21)
        result = self.child(directory, manifest)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue(json.loads(result.stdout)['memoryImportPassed'])

    def test_disk_replacement_after_verification_does_not_change_executed_bytes(self):
        directory, manifest, sources, loader = self.fixture()
        result = self.child(directory, manifest, after="""
for path in pathlib.Path(sys.argv[2]).glob('*.py'):
    path.write_text('raise RuntimeError("FOREIGN_DISK_SOURCE_EXECUTED")')
""")
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_missing_extra_tampered_or_unprotected_members_deny_before_any_import(self):
        for case in ('missing', 'extra', 'source', 'loader', 'mode', 'hardlink', 'symlink'):
            with self.subTest(case=case):
                directory, manifest, sources, loader = self.fixture()
                source = directory / sealed.filename(sealed.ENTRY)
                if case == 'missing':
                    source.unlink()
                elif case == 'extra':
                    (directory / 'foreign.py').write_text('pass')
                elif case == 'source':
                    source.write_text('raise RuntimeError("UNAPPROVED")')
                elif case == 'loader':
                    (directory / 'sealed-runtime.py').write_text('pass')
                elif case == 'mode':
                    source.chmod(0o644)
                elif case == 'hardlink':
                    os.link(source, directory.parent / (directory.name + '-hardlink'))
                    self.addCleanup((directory.parent / (directory.name + '-hardlink')).unlink)
                else:
                    source.unlink()
                    source.symlink_to(LOADER)
                with self.assertRaises(sealed.ClosureDenied):
                    sealed.verify_bundle(directory, sealed.digest(manifest), loader)

    def test_changed_manifest_wrong_closure_or_loader_execution_are_denied(self):
        directory, manifest, sources, loader = self.fixture()
        for approved, executed in [('b' * 64, loader), (sealed.digest(manifest), b'foreign')]:
            with self.assertRaises(sealed.ClosureDenied):
                sealed.verify_bundle(directory, approved, executed)
        changed = {**manifest, 'runtimeAuthorityIssued': True}
        (directory / 'closure.json').write_bytes(sealed.encoded(changed))
        with self.assertRaises(sealed.ClosureDenied):
            sealed.verify_bundle(directory, sealed.digest(changed), loader)

    def test_preloaded_foreign_tools_namespace_is_denied(self):
        directory, manifest, sources, loader = self.fixture()
        result = self.child(directory, manifest, prelude="import types;sys.modules['tools']=types.ModuleType('tools')\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'PRELOADED_RUNTIME_MODULE_DENIED', result.stderr)

    def test_unknown_local_module_cannot_fall_back_to_disk(self):
        directory, manifest, sources, loader = self.fixture()
        result = self.child(directory, manifest, tail="""
try:
    __import__('tools.unapproved_runtime')
except sealed.ClosureDenied as e:
    assert str(e)=='LOCAL_IMPORT_FALLBACK_DENIED'
else:
    raise AssertionError('Fallback permitted')
""")
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_incomplete_source_map_unreviewed_import_and_duplicate_manifest_key_deny(self):
        directory, manifest, sources, loader = self.fixture()
        missing = dict(sources)
        missing.pop('cutover_authority')
        with self.assertRaises(sealed.ClosureDenied):
            sealed.declaration('a' * 40, missing, loader)
        for body in (b'import tools.unapproved_runtime', b'__import__("foreign")', b'from . import foreign'):
            with self.assertRaises(sealed.ClosureDenied):
                sealed.declaration('a' * 40, {**sources, sealed.ENTRY: body}, loader)
        raw = sealed.encoded(manifest)
        (directory / 'closure.json').write_bytes(b'{"entryModule":"duplicate",' + raw[1:])
        with self.assertRaises(sealed.ClosureDenied):
            sealed.verify_bundle(directory, sealed.digest(manifest), loader)

    def test_unprotected_ancestry_and_nonisolated_process_are_denied(self):
        directory, manifest, sources, loader = self.fixture()
        directory.chmod(0o770)
        with self.assertRaises(sealed.ClosureDenied):
            sealed.verify_bundle(directory, sealed.digest(manifest), loader)
        directory.chmod(0o700)
        runtime = sealed.verify_bundle(directory, sealed.digest(manifest), loader)
        if not sys.flags.isolated:
            with self.assertRaisesRegex(sealed.ClosureDenied, 'ISOLATED_NO_BYTECODE'):
                runtime.load_entry()

    @unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS') == '1',
                         'Native gid10001 composition runs on the mandatory hosted root fixture')
    def test_memory_loaded_worker_retains_real_tls_authority_and_pause_checks(self):
        directory, manifest, sources, loader = self.fixture()
        result = self.child(directory, manifest, tail="""
sys.path.insert(0,str(pathlib.Path(sys.argv[1]).resolve().parents[2]/'tests'))
import test_installed_token_owner as qualified
import unittest
names=[
 'test_source_authority_and_online_iam_complete_one_retained_owner_operation',
 'test_pause_is_durable_deduplicated_and_stale_response_cannot_reactivate',
 'test_expired_or_changed_human_source_and_unfenced_legacy_writer_deny_before_grant',
 'test_revocation_after_grant_blocks_further_grants_without_replay',
]
suite=unittest.TestSuite(qualified.InstalledOwnerTest(n) for n in names)
result=unittest.TextTestRunner(verbosity=2).run(suite)
assert result.wasSuccessful() and not result.skipped
""")
        self.assertEqual(result.returncode, 0, result.stderr.decode())

if __name__ == '__main__':
    unittest.main()
