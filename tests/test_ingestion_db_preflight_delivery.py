import ast
import hashlib
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ImmutableDbReadDelivery(unittest.TestCase):
    def test_exact_immutable_reader_is_checked_before_sudo(self):
        text = (ROOT/'scripts/launch-ingestion-db-read-preflight-20261020.sh').read_text()
        raw = (ROOT/'scripts/read-ingestion-db-preflight-20261020.py').read_bytes()
        self.assertIn(hashlib.sha256(raw).hexdigest(),text)
        self.assertIn('git/blobs/b9a7ac830b14d971f8fff43cedc8c40dcdb5742c',text)
        self.assertLess(text.index('sha256sum -c -'),text.index('sudo /usr/bin/python3'))
        self.assertLess(text.index('ouf-gh-2.102.0.PNoFbF'),text.index('command -v gh'))
        self.assertIn('-I -B -S',text)
        self.assertIn('os.O_NOFOLLOW',text)
        subprocess.run(['bash','-n',str(ROOT/'scripts/launch-ingestion-db-read-preflight-20261020.sh')],check=True)

    def test_log_path_is_retained_and_stop_exit_code_is_preserved(self):
        text = (ROOT/'scripts/launch-ingestion-db-read-preflight-20261020.sh').read_text()
        body = text[text.index('ouf_report_log()'):text.index('"$ouf_gh" api')]
        test = subprocess.run(['bash','-c','ouf_read=/fixture/preserved\n'+body+'\nexit 7'],capture_output=True)
        self.assertEqual(test.returncode,7)
        self.assertIn(b'/fixture/preserved/read.log',test.stdout)
        self.assertNotIn('rm -',text)

    def test_production_code_does_not_load_retained_executables_or_change_files(self):
        tree = ast.parse((ROOT/'scripts/read-ingestion-db-preflight-20261020.py').read_text())
        calls = {ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n,ast.Call)}
        self.assertFalse({'exec','eval','os.execv','os.replace','os.unlink','os.mkdir','os.chmod','os.chown'} & calls)
        source = (ROOT/'scripts/read-ingestion-db-preflight-20261020.py').read_text()
        self.assertIn("'-v', 'VERBOSITY=sqlstate'",source)
        self.assertIn("'PGPASSFILE=/dev/null'",source)
        self.assertIn("'exec', selected['postgres']['containerId']",source)


if __name__ == '__main__': unittest.main()
