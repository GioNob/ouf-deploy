import ast
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.ingestion_rollout_preparation import oauth_budget_delivery as d


class Delivery(unittest.TestCase):
    def setUp(self):
        self.case = json.loads((ROOT / 'releases/technical-oauth-budget-extension-case-20261021.json').read_bytes())
        self.raw, self.declaration = d.generate(ROOT, self.case)

    def test_committed_artifact_is_reproducible_and_small(self):
        self.assertEqual(self.raw, (ROOT / 'scripts/technical-oauth-budget-extension-20261021.py').read_bytes())
        self.assertLess(len(self.raw), 65536)
        self.assertEqual(set(self.declaration['sourceHashes']), {'snapshot', 'budget'})
        self.assertFalse(self.declaration['credentialOrNetworkModulesAllowed'])
        self.assertFalse(self.declaration['windowOpeningImplemented'])
        self.assertEqual(self.declaration['maximumAdditionalOAuthAttempts'], 4)

    def run_artifact(self, source, mode):
        with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT', str(ROOT))) as folder:
            path = Path(folder) / 'budget.py'; path.write_bytes(source)
            result = subprocess.run([sys.executable, '-I', '-B', '-S', str(path), mode],
                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, '')
        result = json.loads(result.stdout)
        self.assertEqual(result['status'], 'STOP_RECONCILE')
        self.assertEqual(result['oauthRequests'], 0)
        self.assertFalse(result['runtimeAuthorityIssued'])
        self.assertFalse(result['newHumanWindowOpened'])
        return result

    def test_isolated_process_rejects_an_unbound_mode_before_any_grant(self):
        result = self.run_artifact(self.raw, 'login')
        expected = 'ONE_EXPLICIT_BUDGET_MODE_REQUIRED' if os.geteuid() == os.getegid() == 0 else 'ISOLATED_ROOT_BUDGET_CONTROL_REQUIRED'
        self.assertEqual(result['reasonCode'], expected)

    @unittest.skipUnless(os.geteuid() == os.getegid() == 0, 'isolated root bootstrap qualification')
    def test_tampered_case_denied_before_reading_any_target_file(self):
        tree = ast.parse(self.raw)
        values = {n.targets[0].id: ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)}
        changed = copy.deepcopy(values['CASE']); changed['proposedCumulativeCeiling'] = 296
        source = self.raw.decode().replace('CASE=' + repr(values['CASE']), 'CASE=' + repr(changed), 1).encode()
        result = self.run_artifact(source, 'prepare')
        self.assertEqual(result['reasonCode'], 'BUDGET_CASE_CHANGED')
        self.assertEqual(result['phase'], 'VERIFY_BUDGET_SOURCE')

    @unittest.skipUnless(os.geteuid() == os.getegid() == 0, 'isolated root bootstrap qualification')
    def test_unavailable_exact_target_fails_closed_with_private_details_redacted(self):
        # CI has no real target context. No target credentials or services exist.
        result = self.run_artifact(self.raw, 'prepare')
        self.assertEqual(result['phase'], 'EXPLICIT_TECHNICAL_BUDGET_PREPARE')
        self.assertNotIn('Traceback', json.dumps(result))


if __name__ == '__main__': unittest.main()
