"""Contract of ops/vps/registry-owner-upgrade.sh (task-30b): pins and argument cleaning."""
import hashlib
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNBOOK = ROOT / 'ops/vps/registry-owner-upgrade.sh'
BUILDER = ROOT / 'scripts/build-registry-operational-owner-v2-capsule.py'
PACKAGE = 'tools/semantic_registry_operational_owner_v2'
MODULES = ('core', 'store', 'contract', 'guard', 'durable', 'adapter', 'service', 'installation', 'upgrade', 'entry')


def deliveries(text):
    """(sha256, path) for every pinned `get <sha> <path>` line, joining continuations."""
    joined = text.replace('\\\n', ' ')
    result = {}
    for line in joined.splitlines():
        words = line.split()
        if len(words) == 3 and words[0] == 'get' and re.fullmatch('[0-9a-f]{64}', words[1]):
            result[words[2].strip('"').replace('$O', PACKAGE)] = words[1]
    return result


class Runbook(unittest.TestCase):
    def test_pins_shape_and_second_state(self):
        text = RUNBOOK.read_text()
        pins = dict(line.split('=', 1) for line in text.splitlines() if re.match(r'^(C|B|V1|P)=', line))
        self.assertRegex(pins['C'], r'\A[0-9a-f]{40}\Z')
        for key in ('B', 'V1', 'P'):
            self.assertRegex(pins[key], r'\A[0-9a-f]{64}\Z')
        self.assertEqual(pins['V1'], '0b72275fcc2c51be0929ca0ba454de932ae4863af1b2410dd67bef61bf81e91a')
        self.assertIn('get "$B" scripts/build-registry-operational-owner-v2-capsule.py', text)
        pinned = deliveries(text)
        expected = {'releases/semantic-registry-checkpoint-successor-20261023.py',
                    'tools/semantic_authority_mandates/mandates.py', *(PACKAGE + '/' + m + '.py' for m in MODULES)}
        self.assertEqual(set(pinned), expected)
        if set(pins['C']) != {'0'}:
            # The pinned commit carries these exact bytes: after it only the runbook changes.
            self.assertEqual(pins['B'], hashlib.sha256(BUILDER.read_bytes()).hexdigest())
            for path, sha in pinned.items():
                self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), sha, path)

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
