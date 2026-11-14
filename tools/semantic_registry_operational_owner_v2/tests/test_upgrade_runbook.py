"""Contract of ops/vps/registry-owner-upgrade.sh (task-30b): pins and argument cleaning."""
import hashlib
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNBOOK = ROOT / 'ops/vps/registry-owner-upgrade.sh'
BUILDER = ROOT / 'scripts/build-registry-operational-owner-v2-capsule.py'


class Runbook(unittest.TestCase):
    def pins(self):
        text = RUNBOOK.read_text()
        return text, dict(line.split('=', 1) for line in text.splitlines() if re.match(r'^(C|B|K|V1|P)=', line))

    def test_pins_shape_and_second_state(self):
        text, pins = self.pins()
        self.assertRegex(pins['C'], r'\A[0-9a-f]{40}\Z')
        for key in ('B', 'K', 'V1', 'P'):
            self.assertRegex(pins[key], r'\A[0-9a-f]{64}\Z')
        self.assertEqual(pins['V1'], '0b72275fcc2c51be0929ca0ba454de932ae4863af1b2410dd67bef61bf81e91a')
        if set(pins['C']) != {'0'}:
            self.assertEqual(pins['B'], hashlib.sha256(BUILDER.read_bytes()).hexdigest())
        for module in ('core', 'store', 'contract', 'guard', 'durable', 'adapter', 'service', 'installation', 'upgrade',
                       'entry'):
            self.assertIn(' ' + module, text.split('for m in', 1)[1].split(';', 1)[0])

    def test_arguments_are_cleaned_and_validated_before_any_effect(self):
        for argv, expected in ((['prepare', '0'], b'uso: prepare'), (['issue', '/tmp/x', 'a' * 64], b'path della review'),
                               (['install', '/etc/ouf/deploy-snapshots/r/review.json', 'x\r'], b'ricevuti 1 caratteri'),
                               (['explode'], b'uso:')):
            result = subprocess.run(['bash', str(RUNBOOK), *argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=5)
            with self.subTest(argv=argv):
                self.assertEqual(result.returncode, 2)
                self.assertIn(expected, result.stderr)


if __name__ == '__main__':
    unittest.main()
