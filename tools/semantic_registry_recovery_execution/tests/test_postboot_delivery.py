"""Disposable closed-source loader/capsule tests; no target or recovery authority."""
import ast
import base64
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
RUNTIME_PATH = ROOT / 'tools/semantic_registry_recovery_execution/runtime.py'
DELIVERY_PATH = ROOT / 'tools/semantic_registry_recovery_execution/delivery.py'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


r = load('postboot_runtime_fixture_loader', RUNTIME_PATH)
d = load('postboot_delivery_fixture_generator', DELIVERY_PATH)
COMMIT = 'a' * 40
HELPER = 'tools.semantic_registry_recovery_execution.fixture_helper'
ENTRY = b"""def execute(case, manifest, sources, argv):
    import sys
    def unused():
        from .fixture_helper import VALUE
        return VALUE
    return {'fixtureOnly': True, 'mode': argv[0],
            'helperLoadedBeforeEntry': 'tools.semantic_registry_recovery_execution.fixture_helper' in sys.modules,
            'loadedSourceHash': sys.modules[__name__].__qualified_source_sha256__}
"""
SOURCES = {r.ENTRY: ENTRY, HELPER: b'VALUE = 7\n'}


class SealedPostbootDelivery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.write('tools/semantic_registry_recovery_execution/runtime.py', RUNTIME_PATH.read_bytes())
        for name, raw in SOURCES.items():
            self.write(r.source_path(name), raw)

    def write(self, path, raw):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        return target

    def generate(self):
        return d.generate(self.root, {'schema': 'fixture-only'}, COMMIT, {'ouf-deploy': COMMIT})

    def capsule(self, raw, *args):
        self.assertEqual(os.geteuid(), 0, 'protected target-capsule fixture requires root; do not skip qualification')
        p = subprocess.run([sys.executable, '-I', '-B', '-S', '-', *args],
            input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, cwd='/')
        self.assertEqual(p.stderr, b'')
        return p.returncode, json.loads(p.stdout)

    def assignments(self, raw):
        return {node.targets[0].id: ast.literal_eval(node.value) for node in ast.parse(raw).body
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)}

    def render(self, values):
        return ('\n'.join(k + '=' + repr(v) for k, v in values.items())
            + '\nexec(compile(BOOTSTRAP,"<fixture-capsule>","exec"))\n').encode()

    def test_actual_isolated_capsule_preloads_all_sources_without_target_action(self):
        raw, declaration = self.generate()
        code, result = self.capsule(raw, 'prepare')
        self.assertEqual(code, 0)
        self.assertTrue(result['fixtureOnly'])
        self.assertTrue(result['helperLoadedBeforeEntry'])
        self.assertEqual(result['loadedSourceHash'], hashlib.sha256(ENTRY).hexdigest())
        self.assertFalse(declaration['runtimeAuthorityIssued'])

    def test_packaging_is_deterministic_and_records_exact_paths_git_blobs(self):
        raw, declaration = self.generate()
        self.assertEqual(self.generate(), (raw, declaration))
        native = declaration['nativeDeclaration']
        self.assertEqual(native['sourcePaths'][HELPER], r.source_path(HELPER))
        self.assertEqual(native['sourceGitBlobs'][HELPER],
            hashlib.sha1(b'blob 10\0' + SOURCES[HELPER]).hexdigest())
        self.assertEqual(set(native['sourceHashes']), set(SOURCES))

    def test_repository_pin_insertion_order_cannot_change_capsule_bytes(self):
        pins = {'ouf-semantic-registry': 'b'*40, 'ouf-deploy': COMMIT, 'ouf-ingestion-runtime': 'c'*40}
        reverse = dict(reversed(list(pins.items())))
        self.assertEqual(d.generate(self.root, {'schema': 'fixture-only'}, COMMIT, pins),
                         d.generate(self.root, {'schema': 'fixture-only'}, COMMIT, reverse))

    def test_linux_windows_probe_is_explicitly_absent_without_disk_fallback(self):
        finder = r.MemoryLoader({}, frozenset(), {})
        with patch.object(r.sys, 'platform', 'linux'):
            with self.assertRaises(ModuleNotFoundError) as denied:
                finder.find_spec('_wmi')
            self.assertEqual(denied.exception.name, '_wmi')
            with self.assertRaisesRegex(r.RuntimeDenied, 'LOCAL_SOURCE_IMPORT_FALLBACK_DENIED'):
                finder.find_spec('_undeclared_optional_implementation')
        self.assertNotIn('_wmi', sys.modules)

    def test_generated_stdlib_uses_exact_interpreter_path_and_blocks_build_selectors(self):
        selected = r.generated_stdlib_binding()
        self.write(selected[0] + '.py', b'raise AssertionError("UNDECLARED_SYSCONFIG_EXECUTED")\n')
        with patch.object(sys, 'path', [str(self.root), *sys.path]):
            same = r.generated_stdlib_binding()
        self.assertEqual(same[0], selected[0])
        self.assertEqual(same[1].origin, selected[1].origin)
        self.assertEqual(Path(same[1].origin).parent.resolve(), Path(sys._stdlib_dir).resolve())
        finder = r.MemoryLoader({}, frozenset(), {}, selected)
        with self.assertRaisesRegex(r.RuntimeDenied, 'LOCAL_SOURCE_IMPORT_FALLBACK_DENIED'):
            finder.find_spec('_sysconfigdata__unreviewed_build')
        for variable in ('_PYTHON_SYSCONFIGDATA_NAME', '_PYTHON_SYSCONFIGDATA_PATH', '_PYTHON_PROJECT_BASE',
                         '_PYTHON_HOST_PLATFORM', '_PYTHON_BUILD', 'PYTHONUSERBASE', 'DEB_PYTHON_INSTALL_LAYOUT'):
            with self.subTest(variable=variable), patch.dict(os.environ, {variable: ''}):
                with self.assertRaisesRegex(r.RuntimeDenied, 'PYTHON_BUILD_CONFIGURATION_OVERRIDE_DENIED'):
                    r.generated_stdlib_binding()

    def test_missing_static_package_member_and_unreachable_extra_are_rejected(self):
        with self.assertRaisesRegex(r.RuntimeDenied, 'MISSING_STATIC_PACKAGE_MEMBER'):
            r.compile_sources({r.ENTRY: b'from . import absent\n'})
        with self.assertRaisesRegex(r.RuntimeDenied, 'UNREACHABLE_EXTRA_SOURCE_DENIED'):
            r.compile_sources({r.ENTRY: b'VALUE=1\n', HELPER: b'VALUE=2\n'})

    def test_relative_escape_and_nonliteral_dynamic_imports_are_rejected(self):
        for raw, reason in (
            (b'from ..... import escape\n', 'RELATIVE_IMPORT_ESCAPES_PACKAGE'),
            (b'def call(name):\n return __import__(name)\n', 'UNRESOLVED_DYNAMIC_IMPORT_DENIED'),
            (b'import importlib as x\nx.import_module("tools.hidden")\n', 'DYNAMIC_APPLICATION_IMPORT_DENIED'),
            (b'from importlib import import_module as f\ndef call(x):\n return f(x)\n', 'UNRESOLVED_DYNAMIC_IMPORT_DENIED')):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(r.RuntimeDenied, reason):
                    r.compile_sources({r.ENTRY: raw})

    def test_literal_stdlib_dynamic_import_is_closed(self):
        compiled, packages = r.compile_sources({r.ENTRY: b'VALUE=__import__("hashlib").sha256(b"x").hexdigest()\n'})
        self.assertEqual(set(compiled), {r.ENTRY})
        self.assertIn('tools.semantic_registry_recovery_execution', packages)

    def test_shadowing_stdlib_and_undeclared_disk_fallback_are_denied(self):
        with self.assertRaisesRegex(r.RuntimeDenied, 'SOURCE_MODULE_OUTSIDE_CLOSED_NAMESPACE'):
            r.compile_sources({r.ENTRY: b'import json\n', 'json': b'VALUE=1\n'})
        loader = r.MemoryLoader({}, frozenset(), {})
        with self.assertRaisesRegex(r.RuntimeDenied, 'LOCAL_SOURCE_IMPORT_FALLBACK_DENIED'):
            loader.find_spec('tools.other_service')
        with self.assertRaisesRegex(r.RuntimeDenied, 'LOCAL_SOURCE_IMPORT_FALLBACK_DENIED'):
            loader.find_spec('engine_creation')

    def test_declared_hash_change_rejected_before_import(self):
        sources = dict(SOURCES)
        loader = RUNTIME_PATH.read_bytes()
        manifest = r.declaration(COMMIT, sources, loader, {'ouf-deploy': COMMIT})
        program = ('import json\nns={}\nexec(' + repr(loader)
            + ',ns)\nsources=' + repr({**sources, HELPER: b'VALUE=8\n'})
            + '\ntry:\n ns["load_entry"](' + repr(COMMIT) + ',sources,' + repr(loader)
            + ',' + repr(r.digest(manifest)) + ',' + repr({'ouf-deploy': COMMIT})
            + ')\nexcept Exception as e:\n print(str(e))\n')
        result = subprocess.run([sys.executable, '-I', '-B', '-S', '-'], input=program.encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), b'APPROVED_SOURCE_DECLARATION_CHANGED')

    def test_preloaded_foreign_namespace_rejected(self):
        loader = RUNTIME_PATH.read_bytes()
        manifest = r.declaration(COMMIT, SOURCES, loader, {'ouf-deploy': COMMIT})
        program = ('import sys,types\nns={}\nexec(' + repr(loader)
            + ',ns)\nsys.modules["tools"]=types.ModuleType("tools")\ntry:\n ns["load_entry"]('
            + repr(COMMIT) + ',' + repr(SOURCES) + ',' + repr(loader) + ','
            + repr(r.digest(manifest)) + ',' + repr({'ouf-deploy': COMMIT})
            + ')\nexcept Exception as e:\n print(str(e))\n')
        result = subprocess.run([sys.executable, '-I', '-B', '-S', '-'], input=program.encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), b'PRELOADED_APPLICATION_MODULE_DENIED')

    def test_capsule_mode_and_case_tampering_stop_before_entry(self):
        raw, _ = self.generate()
        code, result = self.capsule(raw, 'restart')
        self.assertEqual(code, 2)
        self.assertEqual(result['reasonCode'], 'ONE_EXPLICIT_POSTBOOT_MODE_REQUIRED')
        values = self.assignments(raw)
        values['CASE']['arbitrary'] = True
        code, result = self.capsule(self.render(values), 'prepare')
        self.assertEqual(code, 2)
        self.assertEqual(result['reasonCode'], 'POSTBOOT_CASE_CHANGED')
        self.assertFalse(result['runtimeEffectsMayBePartial'])

    def test_source_payload_tampering_is_rejected_before_execution(self):
        raw, _ = self.generate()
        values = self.assignments(raw)
        payload = json.loads(gzip.decompress(base64.b64decode(values['PACKED'])))
        payload['sources'][r.ENTRY] = 'raise RuntimeError("UNVERIFIED_EXECUTED")\n'
        values['PACKED'] = base64.b64encode(gzip.compress(d.encoded(payload), mtime=0)).decode()
        code, result = self.capsule(self.render(values), 'prepare')
        self.assertEqual(code, 2)
        self.assertEqual(result['reasonCode'], 'POSTBOOT_SOURCE_BYTES_CHANGED')
        self.assertNotIn('UNVERIFIED_EXECUTED', json.dumps(result))

    def test_entry_error_does_not_expose_private_values_or_claim_zero_effects(self):
        self.write(r.source_path(r.ENTRY),
            b'def execute(*args):\n raise RuntimeError("fixture-private-value/42")\n')
        raw, _ = self.generate()
        code, result = self.capsule(raw, 'continue')
        self.assertEqual(code, 2)
        self.assertEqual(result['reasonCode'], 'POSTBOOT_OUTCOME_UNPROVEN_PRIVATE_DETAILS_REDACTED')
        self.assertTrue(result['runtimeEffectsMayBePartial'])
        self.assertNotIn('fixture-private-value', json.dumps(result))
        self.assertNotIn('oauthRequests', result)

    def test_symlink_source_and_unresolved_static_source_stop_packaging(self):
        path = self.root / r.source_path(HELPER)
        saved = path.with_name('saved.py')
        path.rename(saved); path.symlink_to(saved)
        with self.assertRaisesRegex(ValueError, 'SOURCE_PATH_SYMLINK_OR_ESCAPE'):
            self.generate()
        path.unlink(); saved.rename(path)
        self.write(r.source_path(r.ENTRY), b'from .absent import VALUE\n')
        with self.assertRaisesRegex(ValueError, 'UNRESOLVED_SOURCE_PACKAGE_DEPENDENCY'):
            self.generate()

    def test_source_size_bound_is_enforced(self):
        with self.assertRaisesRegex(r.RuntimeDenied, 'BOUNDED_COMPLETE_RECOVERY_SOURCES_REQUIRED'):
            r.compile_sources({r.ENTRY: b'#' * (r.MAX_SOURCE_BYTES + 1)})


if __name__ == '__main__':
    unittest.main()
