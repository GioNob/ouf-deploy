"""Public process error boundary only; runtime dependencies tested natively."""
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT))
from tools.semantic_registry_operational_owner import entry
from tools.semantic_registry_operational_owner.core import Denied


class Boundary(unittest.TestCase):
    def test_untrusted_exception_message_never_reaches_public_output(self):
        output=io.StringIO()
        with patch.object(entry,'main',side_effect=OSError('DISPOSABLE_SECRET https://fixture.invalid')):
            with contextlib.redirect_stdout(output):result=entry.execute([])
        self.assertEqual(result,2);self.assertNotIn('DISPOSABLE_SECRET',output.getvalue())
        self.assertNotIn('fixture.invalid',output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['status'],'STOP_RECONCILE')

    def test_owned_reason_is_fixed_code_without_false_success_or_replay_claim(self):
        output=io.StringIO()
        with patch.object(entry,'main',side_effect=Denied('OPERATIONAL_OWNER_FENCE_CHANGED')):
            with contextlib.redirect_stdout(output):self.assertEqual(entry.execute([]),2)
        value=json.loads(output.getvalue())
        self.assertEqual(value['reasonCode'],'OPERATIONAL_OWNER_FENCE_CHANGED')
        self.assertTrue(value['outcomeRequiresReconciliation']);self.assertFalse(value['automaticReplayAllowed'])


if __name__=='__main__':unittest.main()
