"""Exact documented reader delivery with gh outside PATH and inert sudo."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
READER=ROOT/'tools/semantic_target_review/read_r7_rootfs_differences.py'


class R7ReadDeliveryTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.bin=self.root/'bin';self.bin.mkdir()
        self.gh=self.root/'retained-gh'
        self.gh.write_text('#!'+sys.executable+'''\nimport base64,os,pathlib,sys
route=next(x for x in sys.argv if x.startswith('repos/'))
assert route=='repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/read_r7_rootfs_differences.py?ref=4e57d2b8fb6f9ae081bca71650a43ee636fc31b5'
if os.environ.get('CI_DOWNLOAD_FAIL'):raise SystemExit(22)
raw=pathlib.Path(os.environ['CI_READER']).read_bytes()
if os.environ.get('CI_TAMPER'):raw+=b'\\n'
print(base64.b64encode(raw).decode())
''');self.gh.chmod(0o755)
        sudo=self.bin/'sudo';sudo.write_text('#!'+sys.executable+'''\nimport json,os,pathlib,sys
pathlib.Path(os.environ['CI_MARKER']).write_text(json.dumps(sys.argv[1:]))
raise SystemExit(int(os.environ.get('CI_ROOT_EXIT','0')))
''');sudo.chmod(0o755)
        for name in ('mktemp','base64','sha256sum'):(self.bin/name).symlink_to('/usr/bin/'+name)
        self.env={**os.environ,'PATH':str(self.bin),'CI_READER':str(READER),'CI_MARKER':str(self.root/'sudo.json')}

    def run_command(self,**overrides):
        document=(ROOT/'releases/PROVIDER_R7_ROOTFS_DIAGNOSIS_20261009.md').read_text()
        command=document.split('```bash\n',1)[1].split('```',1)[0]
        command=command.replace('$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh',str(self.gh))
        command=command.replace('$HOME/ouf-r7-rootfs-read.',str(self.root/'ouf-r7-rootfs-read.'))
        return subprocess.run(['/bin/bash','-c',command],env={**self.env,**overrides},
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)

    def test_exact_reader_and_root_recheck_delivered_with_gh_absent_from_path(self):
        result=self.run_command()
        self.assertIn(b'OUF_R7_ROOTFS_READ_EXIT=0',result.stdout,result.stderr.decode())
        argv=json.loads((self.root/'sudo.json').read_text())
        self.assertEqual(argv[:4],['/usr/bin/python3.13','-I','-B','-c'])
        self.assertEqual(len(argv),6)
        self.assertEqual(Path(argv[-1]).read_bytes(),READER.read_bytes())
        self.assertIn(hashlib.sha256(READER.read_bytes()).hexdigest(),argv[4])
        self.assertIn('sys.argv = [p]',argv[4])

    def test_download_error_or_changed_hash_never_reaches_sudo(self):
        for env in ({'CI_DOWNLOAD_FAIL':'1'},{'CI_TAMPER':'1'}):
            with self.subTest(env=env):
                result=self.run_command(**env)
                self.assertIn(b'OUF_R7_ROOTFS_READ_EXIT=1',result.stdout)
                self.assertFalse((self.root/'sudo.json').exists())

    def test_missing_known_gh_never_downloads_or_reaches_sudo(self):
        self.gh.unlink();result=self.run_command()
        self.assertIn(b'EXISTING_GH_NOT_EXECUTABLE',result.stdout)
        self.assertFalse((self.root/'sudo.json').exists())
        self.assertEqual(list(self.root.glob('ouf-r7-rootfs-read.*')),[])

    def test_root_failure_is_reported_without_retry(self):
        result=self.run_command(CI_ROOT_EXIT='37')
        self.assertIn(b'OUF_R7_ROOTFS_READ_EXIT=37',result.stdout)
        self.assertEqual(len(list(self.root.glob('ouf-r7-rootfs-read.*'))),1)


if __name__=='__main__':unittest.main()
