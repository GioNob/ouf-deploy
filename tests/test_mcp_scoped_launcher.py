"""Pinned launcher consistency and native root byte-custody, using inert executor."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / 'scripts/launch-semantic-mcp-policy-remainder-20261017.sh'
SOURCE = 'c651d4d6d404facc96d8455180a95103c8059152'

def body():
    return LAUNCHER.read_text().split("<<'PYROOT' 2>&1 | tee \"$ouf_stage/run.log\"\n", 1)[1].rsplit('PYROOT\n', 1)[0]

class LauncherPins(unittest.TestCase):
    def test_all_downloaded_bytes_and_root_pins_match_manifest(self):
        package_path = ROOT / 'releases/semantic-mcp-scoped-token-package-20261017.json'
        package = json.loads(package_path.read_bytes())
        tree = ast.parse(body())
        expected = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'expected' for t in n.targets))
        self.assertEqual(set(expected), set(package['files']) | {'package.json'})
        self.assertEqual(package['sourceCommit'], SOURCE)
        shell = LAUNCHER.read_text()
        for name, row in package['files'].items():
            self.assertEqual(expected[name], (row['sha256'], row['maximumBytes']))
            self.assertRegex(row['sha256'], r'^[a-f0-9]{64}$')  # Retained package pins frozen source, not the changing checkout.
            self.assertIn(row['path'] + ' ' + name, shell)
            self.assertIn("'" + row['sha256'] + "' \"$ouf_stage/" + name + '"', shell)
        self.assertEqual(expected['package.json'][0], hashlib.sha256(package_path.read_bytes()).hexdigest())
        self.assertIn("ouf_source_ref='" + SOURCE + "'", shell)
        subprocess.run(['bash', '-n', str(LAUNCHER)], check=True)

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS') == '1' and os.geteuid() == 0 and os.getegid() == 0, 'native root custody fixture in GitHub Actions')
class RootCustody(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT', '/tmp'))
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.stage = self.base / 'input'; self.stage.mkdir(mode=0o700)
        self.dest = self.base / 'custody'; self.dest.mkdir(mode=0o700)
        self.marker = self.base / 'executed'
        inert = "import sys\nfrom pathlib import Path\nassert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode\nassert sys.argv[2:] == [" + repr(SOURCE) + ", 'TOKEN_SESSION']\nPath(" + repr(str(self.marker)) + ").write_text('inert fixture executed')\n"
        self.inputs = {'execute.py': inert.encode(), 'package.json': json.dumps({'sourceCommit': SOURCE, 'mode': 'TOKEN_SESSION'}).encode(), 'fixture.py': b'# inert retained bytes\n'}
        pins = {n: (hashlib.sha256(v).hexdigest(), 131072) for n, v in self.inputs.items()}
        for name, value in self.inputs.items():
            (self.stage/name).write_bytes(value)
        tree = ast.parse(body())
        # Keep the actual root-copy and isolated subprocess implementation; replace only fixture inputs/destination.
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'expected' for t in node.targets):
                node.value = ast.parse(repr(pins), mode='eval').body
        class Destination(ast.NodeTransformer):
            def visit_Constant(inner, node):
                if node.value == '/etc/ouf/deploy-snapshots':
                    return ast.copy_location(ast.Constant(str(self.dest)), node)
                return node
        tree = Destination().visit(tree); ast.fix_missing_locations(tree)
        self.script = ast.unparse(tree)

    def run_fixture(self):
        return subprocess.run([sys.executable, '-u', '-I', '-B', '-S', '-', str(self.stage)], input=self.script, text=True, capture_output=True, timeout=10)

    def test_exact_bytes_copied_then_isolated_executor_started(self):
        result = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.marker.exists())
        code = Path(next(line.split('=', 1)[1] for line in result.stdout.splitlines() if line.startswith('OUF_SCOPED_EXECUTOR_CODE=')))
        for name, value in self.inputs.items():
            self.assertEqual((code/name).read_bytes(), value)
            self.assertEqual(stat.S_IMODE((code/name).stat().st_mode), 0o600)
            self.assertEqual((code/name).stat().st_uid, 0)

    def test_tampered_bytes_fail_before_execution(self):
        (self.stage/'fixture.py').write_bytes(b'# tampered\n')
        self.assertNotEqual(self.run_fixture().returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_symlink_fails_before_execution(self):
        target = self.stage/'fixture.py'; target.unlink(); target.symlink_to(self.stage/'execute.py')
        self.assertNotEqual(self.run_fixture().returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_hardlink_fails_before_execution(self):
        os.link(self.stage/'fixture.py', self.base/'extra-link')
        self.assertNotEqual(self.run_fixture().returncode, 0)
        self.assertFalse(self.marker.exists())

if __name__ == '__main__': unittest.main()
