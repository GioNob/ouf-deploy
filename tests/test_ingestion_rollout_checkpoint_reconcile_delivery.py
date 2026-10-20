import hashlib
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Delivery(unittest.TestCase):
    def test_immutable_source_and_pre_sudo_hash(self):
        launcher = ROOT / 'scripts/launch-ingestion-rollout-checkpoint-reconcile-20261020.sh'
        text = launcher.read_text()
        source = (ROOT / 'scripts/read-ingestion-rollout-checkpoint-reconcile-20261020.py').read_bytes()
        self.assertIn(hashlib.sha256(source).hexdigest(), text)
        self.assertIn('git/blobs/b55877863730fdb6b59b43483690c29365764c3a', text)
        self.assertLess(text.index('sha256sum -c -'), text.index('sudo /usr/bin/python3'))
        self.assertLess(text.index('ouf-gh-2.102.0.PNoFbF'), text.index('command -v gh'))
        self.assertIn('set -euo pipefail', text)
        self.assertIn('os.O_NOFOLLOW', text)
        self.assertNotRegex(text, r'gh (auth|api.*login)|docker (start|run|restart)|\b(curl|ssh)\b')
        subprocess.run(['bash', '-n', str(launcher)], check=True)

    def test_production_reader_has_no_dispatch_or_mutating_imports(self):
        import ast
        source = (ROOT / 'scripts/read-ingestion-rollout-checkpoint-reconcile-20261020.py').read_text()
        tree = ast.parse(source)
        imports = [node.names[0].name.split('.')[0] for node in ast.walk(tree) if isinstance(node, ast.Import)]
        self.assertNotIn('subprocess', imports)
        self.assertNotIn('urllib', imports)
        self.assertNotIn('tools', imports)
        calls = {ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
        self.assertFalse({'exec', 'eval', 'os.execv', 'os.replace', 'os.unlink', 'os.mkdir', 'os.chmod'} & calls)
        self.assertEqual(re.findall(r"connection.request\('([^']+)'", source), ['GET'])


if __name__ == '__main__': unittest.main()
