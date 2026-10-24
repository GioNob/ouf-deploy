"""Exercise the actual main exception path which the native fixture missed."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/apply-onboarding-v35-native-20261024.py'

class MainFailureTests(unittest.TestCase):
    def test_actual_main_preserves_stop_and_redacts_unrecognized_errors(self):
        spec = importlib.util.spec_from_file_location('v35_entry_failure_test', SOURCE)
        entry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(entry)
        ctx = types.SimpleNamespace(root=Path('/retained-existing-claim'))
        cases = [(entry.Stop('EXACT_V35_REPLACEMENT_CONFIG_REQUIRED'), 'EXACT_V35_REPLACEMENT_CONFIG_REQUIRED'),
                 (RuntimeError('SECRET_TOKEN_VALUE'), 'V35_NATIVE_EXECUTION_UNPROVEN'),
                 (entry.Stop('SECRET_TOKEN_VALUE=private'), 'V35_NATIVE_EXECUTION_UNPROVEN')]
        for error, reason in cases:
            with self.subTest(reason=reason), contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(entry.os, 'geteuid', return_value=0))
                stack.enter_context(patch.object(entry.os, 'getegid', return_value=0))
                stack.enter_context(patch.object(entry.sys, 'flags', types.SimpleNamespace(isolated=True, no_site=True)))
                stack.enter_context(patch.object(entry.sys, 'dont_write_bytecode', True))
                stack.enter_context(patch.object(entry.sys, 'argv', ['apply.py']))
                stack.enter_context(patch.object(entry.signal, 'signal'))
                bootstrap = stack.enter_context(patch.object(entry, 'bootstrap', return_value=ctx))
                operator = stack.enter_context(patch.object(entry, 'operator', side_effect=error))
                output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                self.assertEqual(entry.main(), 2)
                row = json.loads(output.getvalue())
                self.assertEqual(row['status'], 'STOP_RECONCILE')
                self.assertEqual(row['reasonCode'], reason)
                self.assertEqual(row['contextPath'], str(ctx.root))
                self.assertTrue(row['runtimeEffectsMayBePartial'])
                for field in ('complete', 'automaticReplayAllowed', 'budgetReset', 'releaseAcceptance', 'automaticRollbackPerformed'):
                    self.assertIs(row[field], False)
                self.assertNotIn('SECRET_TOKEN_VALUE', output.getvalue())
                bootstrap.assert_called_once_with()
                operator.assert_called_once_with(ctx)

if __name__ == '__main__':
    unittest.main()
