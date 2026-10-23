"""Actual shell/hash/private-copy/replay refusal with explicit GitHub/sudo fixtures.

The capsule is a synthetic no-effect fixture; these are delivery checks, not
installer/IAM/systemd/target qualification. Native suites test those separately.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('operational_launcher_renderer',ROOT/'scripts/build-registry-operational-owner-launcher.py')
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)


class Delivery(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.home=self.root/'home';self.home.mkdir(mode=0o700)
        self.parent=self.root/'private';self.parent.mkdir(mode=0o700)
        self.marker=self.root/'executed'
        self.raw=('from pathlib import Path\nPath('+repr(str(self.marker))+').write_text("one invocation")\nprint("SYNTHETIC_NO_EFFECT_CAPSULE")\n').encode()
        self.fixture=self.root/'fixture.py';self.fixture.write_bytes(self.raw)
        self.sha=hashlib.sha256(self.raw).hexdigest()
        self.gh=self.home/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
        self.gh.parent.mkdir(parents=True)
        self.gh.write_text('#!/usr/bin/python3\nimport sys\nsys.stdout.buffer.write(open('+repr(str(self.fixture))+',"rb").read())\n');self.gh.chmod(0o700)
        self.sudo=self.root/'fixture-sudo';self.sudo.write_text('#!/usr/bin/python3\nimport os,sys\nif sys.argv[1:]==["-v"]:raise SystemExit(0)\nos.execv(sys.argv[1],sys.argv[1:])\n');self.sudo.chmod(0o700)
        commands=dict(builder.DEFAULT_COMMANDS,sudo=str(self.sudo))
        self.script=self.root/'run.sh';self.script.write_text(builder.render('a'*40,self.sha,parent=str(self.parent),commands=commands))
    def run_script(self):
        return subprocess.run(['/bin/bash',str(self.script)],capture_output=True,text=True,timeout=10,
            env={'PATH':'/usr/bin:/bin','HOME':str(self.home)})
    def test_shell_executes_only_verified_private_copy_once_with_preserved_log(self):
        result=self.run_script();self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(self.marker.exists());root=self.parent/('semantic-registry-operational-launch-'+self.sha[:32])
        self.assertEqual((root/'capsule.py').read_bytes(),self.raw)
        self.assertEqual((root/'capsule.py').stat().st_mode&0o777,0o400)
        self.assertEqual(root.stat().st_mode&0o777,0o700)
        self.assertIn('Directory conservata:',result.stdout)
        self.assertIn('SYNTHETIC_NO_EFFECT_CAPSULE',next(self.home.glob('*/operator.log')).read_text())
    def test_corrupt_download_stops_before_private_directory_or_execution(self):
        self.fixture.write_bytes(b'NOT_REVIEWED')
        result=self.run_script();self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.marker.exists());self.assertEqual(list(self.parent.iterdir()),[])
    def test_same_delivery_cannot_reinvoke_existing_private_launch(self):
        self.assertEqual(self.run_script().returncode,0)
        before=self.marker.stat().st_mtime_ns;self.assertNotEqual(self.run_script().returncode,0)
        self.assertEqual(self.marker.stat().st_mtime_ns,before)
    def test_missing_existing_github_client_stops_before_any_private_effect(self):
        self.gh.unlink();result=self.run_script();self.assertEqual(result.returncode,2)
        self.assertIn('EXISTING_AUTHENTICATED_GITHUB_CLIENT_REQUIRED',result.stderr)
        self.assertFalse(self.marker.exists());self.assertEqual(list(self.parent.iterdir()),[])
    def test_capsule_failure_is_not_hidden_by_tee_success(self):
        self.raw=b'raise SystemExit(2)\n';self.fixture.write_bytes(self.raw)
        sha=hashlib.sha256(self.raw).hexdigest();commands=dict(builder.DEFAULT_COMMANDS,sudo=str(self.sudo))
        self.script.write_text(builder.render('a'*40,sha,parent=str(self.parent),commands=commands))
        result=self.run_script();self.assertEqual(result.returncode,2);self.assertIn('non rilanciare',result.stderr)


if __name__=='__main__':unittest.main()
