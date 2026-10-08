import importlib.util
from pathlib import Path
import unittest
import types

import diagnose_provider_v2_launch_inputs as d


class DiagnosisTests(unittest.TestCase):
    def tearDown(self):
        d.STACK.clear(); d.FAILURE_STACK.clear()

    def test_private_error_text_never_printed(self):
        for error in (KeyError('private-credential'), ValueError('PRIVATE_CREDENTIAL_VALUE'),
                      PermissionError('/private/key'), TypeError('secret environment')):
            self.assertEqual(d.error_label(error, {'SOURCE_DRIFT'}), 'REDACTED_ERROR')
        self.assertEqual(d.error_label(ValueError('SOURCE_DRIFT'), {'SOURCE_DRIFT'}), 'SOURCE_DRIFT')

    def test_only_static_public_labels_allowed(self):
        self.assertEqual(d.labels(b"reason='SOURCE_DRIFT'\nprivate='not an error'"), {'SOURCE_DRIFT'})

    def test_nested_failure_chain_is_bounded_function_names(self):
        module = types.SimpleNamespace()
        def inner():
            raise KeyError('private')
        module.inner = inner
        module.outer = lambda: module.inner()
        d.wrap(module, 'inner', 'reader'); d.wrap(module, 'outer', 'reader')
        with self.assertRaises(KeyError):
            module.outer()
        self.assertEqual(d.FAILURE_STACK, ['reader.outer', 'reader.inner'])
        self.assertEqual(d.STACK, [])

    def test_existing_sealed_reader_has_no_main_side_effect_on_import(self):
        path = Path(__file__).parent.parent / 'provider-v2-create/resume-provider-v2-stopped.py'
        if not path.exists():
            self.skipTest('local source fixture only')
        spec = importlib.util.spec_from_file_location('_ouf_test_read_only', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.assertTrue(callable(module.prepare))
        self.assertTrue(callable(module.verify_container))


if __name__ == '__main__':
    unittest.main()
