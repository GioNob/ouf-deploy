"""Task-33: governed early renewal with the installed job, native fixture of task-28."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import unittest

import test_semantic_mandate_renewal as base

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'scripts/renew-mandates-early.py'
RUNBOOK = ROOT / 'ops/vps/mandate-renewal-early.sh'
DAY = base.DAY


def load_tool():
    spec = importlib.util.spec_from_file_location('renew_mandates_early', TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Early(base.Fixture):
    def setUp(self):
        super().setUp()
        self.t = load_tool()
        self.now = base.END - 49 * DAY  # far beyond T-30: the daily job would NOOP

    def early_job(self, digest=None):
        return self.t.installed_job(str(self.config_path), digest or base.sha(self.config_path.read_bytes()), self.clock)

    def test_daily_job_noops_but_early_plan_renews_both(self):
        self.assertEqual(self.execute(), ('NOOP', None, False))
        module, job = self.early_job()
        first = self.t.plan(module, job, self.now)
        self.assertEqual(first['renew'], ['b1b2', 'base'])
        self.assertEqual(first['thresholdSeconds'], 7776000 - 86400)
        self.assertEqual(self.t.digest(first), self.t.digest(self.t.plan(*self.early_job(), self.now)))
        self.assertEqual(self.names(self.ledgers / 'base'), [])

    def test_apply_renews_once_then_nothing_to_renew(self):
        module, job = self.early_job()
        approved = self.t.digest(self.t.plan(module, job, self.now))
        with self.assertRaises(self.t.Held):
            self.t.apply(*self.early_job(), '0' * 64, self.now)
        self.assertEqual(self.names(self.ledgers / 'b1b2'), [])
        result = self.t.apply(*self.early_job(), approved, self.now)
        self.assertEqual((result['status'], result['outcome']), ('EARLY_RENEWAL_APPLIED', 'RENEWED'))
        for name in ('b1b2', 'base'):
            record = json.loads((self.ledgers / name / '1.json').read_bytes())
            self.assertTrue(all(m['expiresAt'] == self.now + 90 * DAY for m in record['mandates']))
        self.assertEqual(self.names(self.ledgers / 'base-versioned'), ['1.json'])
        self.assertFalse(result['openIncident'])
        with self.assertRaises(self.t.Held) as caught:
            self.t.plan(*self.early_job(), self.now + 60)
        self.assertEqual(str(caught.exception), 'NOTHING_TO_RENEW_EARLY')
        # The installed daily job sees a fresh 90-day window: NOOP.
        self.now += 60
        self.assertEqual(self.execute()[0], 'NOOP')

    def test_open_incident_or_configuration_drift_refused(self):
        (self.state / 'incidents').mkdir(mode=0o700)
        self.write(self.state / 'incidents/open.json', {'reasonCode': 'FIRST', 'firstSeenAt': 1, 'evidenceSha256': None})
        with self.assertRaises(self.t.Held) as caught:
            self.t.plan(*self.early_job(), self.now)
        self.assertEqual(str(caught.exception), 'OPEN_INCIDENT_PRESENT')
        with self.assertRaises(self.t.Held):
            self.early_job('0' * 64)

    def test_threshold_is_lowered_only_after_configuration_validation(self):
        module, _ = self.early_job()
        self.assertEqual(module.RENEW_BEFORE_SECONDS, 7776000 - 86400)
        fresh = base.load(self.renewal_path, 'renewal_untouched')
        self.assertEqual(fresh.RENEW_BEFORE_SECONDS, 2592000)


class RunbookContract(unittest.TestCase):
    def test_pins_and_arguments(self):
        text = RUNBOOK.read_text()
        pins = dict(line.split('=', 1) for line in text.splitlines() if re.match(r'^(C|T)=', line))
        self.assertRegex(pins['C'], r'\A[0-9a-f]{40}\Z')
        self.assertRegex(pins['T'], r'\A[0-9a-f]{64}\Z')
        if set(pins['C']) != {'0'}:
            self.assertEqual(pins['T'], hashlib.sha256(TOOL.read_bytes()).hexdigest())
        result = subprocess.run(['bash', str(RUNBOOK), 'apply', 'x\r'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'ricevuti 1 caratteri', result.stderr)


if __name__ == '__main__':
    unittest.main()
