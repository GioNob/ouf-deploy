"""The delivery prerequisite check must fail explicitly, before any download."""
import os,subprocess,tempfile,unittest
from pathlib import Path
SOURCE=Path(__file__).resolve().parents[1]/'releases/stage-acquisition-read-packages-20261025.sh'
class DeliveryPrerequisiteTest(unittest.TestCase):
    def check(self,names):
        text=SOURCE.read_text();guard=text[text.index('  for dependency in gh timeout; do'):text.index("  timeout --signal=TERM")]
        with tempfile.TemporaryDirectory()as directory:
            for name in names:
                target=Path(directory,name);target.write_text('#!/bin/sh\nexit 0\n');target.chmod(0o700)
            return subprocess.run(['/bin/bash','-c',guard],env={'PATH':directory},capture_output=True,text=True)
    def test_missing_gh_reports_exact_dependency_without_running_download(self):
        result=self.check([]);self.assertEqual(result.returncode,127);self.assertIn('MissingCommand=gh',result.stdout);self.assertIn('RuntimeStageInvoked=false',result.stdout)
    def test_missing_timeout_reports_exact_dependency(self):
        result=self.check(['gh']);self.assertEqual(result.returncode,127);self.assertIn('MissingCommand=timeout',result.stdout)
    def test_present_tools_do_not_fail(self):
        result=self.check(['gh','timeout']);self.assertEqual(result.returncode,0);self.assertEqual(result.stdout,'')
if __name__=='__main__':unittest.main()
