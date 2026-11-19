"""Exact public download/FD hash gate; inspect only, no target input capture."""
import hashlib, json, os, subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


class Launcher(unittest.TestCase):
    def prepared(self, content=None):
        tmp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(tmp.cleanup)
        root=Path(tmp.name);root.chmod(0o700);bin_dir=root/'bin';bin_dir.mkdir()
        source=root/'fixture.py';source.write_bytes(content if content is not None else
            (ROOT/'scripts/capture-m2-retained-mounts-20261101.py').read_bytes())
        curl=bin_dir/'curl';curl.write_text('''#!/bin/sh
set -eu
out=''
while [ "$#" -gt 0 ]; do
 case "$1" in --output) out="$2"; shift 2 ;; *) shift ;; esac
done
/bin/cp -- "$OUF_PUBLIC_CAPSULE_FIXTURE" "$out"
''');curl.chmod(0o755)
        env={**os.environ,'PATH':str(bin_dir)+':/usr/bin:/bin','TMPDIR':str(root),'OUF_PUBLIC_CAPSULE_FIXTURE':str(source)}
        return root,env

    def run_launcher(self,env,*args):
        return subprocess.run(['/bin/bash',str(ROOT/'scripts/launch-m2-retained-mount-capture-20261101.sh'),*args],
            env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)

    def test_downloaded_exact_bytes_execute_only_the_isolated_source_inspector(self):
        _,env=self.prepared();result=self.run_launcher(env,'--inspect-source')
        self.assertEqual(result.returncode,0,result.stderr);body=json.loads(result.stdout)
        self.assertEqual(body['sourceRevisionClaim'],'26b7fb1260ea72a67ae635019e21d8eedbc9c42b')
        self.assertEqual(body['sourceCount'],2);self.assertFalse(body['targetApplyAuthorized'])

    def test_changed_empty_or_oversized_download_never_executes_its_body(self):
        for raw in (b'print("UNTRUSTED_BODY_EXECUTED")',b'',b'x'*262145):
            _,env=self.prepared(raw);result=self.run_launcher(env,'--inspect-source')
            self.assertNotEqual(result.returncode,0);self.assertNotIn(b'UNTRUSTED_BODY_EXECUTED',result.stdout+result.stderr)
            self.assertEqual(json.loads(result.stdout)['reasonCode'],'EXACT_CAPTURE_DOWNLOAD_UNPROVEN')

    def test_unknown_or_extra_args_are_rejected_without_echo_or_download(self):
        _,env=self.prepared();sentinel='PRIVATE_ARGUMENT_MUST_NOT_ECHO'
        for args in (('--unknown',sentinel),('--inspect-source',sentinel),('',)):
            result=self.run_launcher(env,*args);self.assertNotEqual(result.returncode,0)
            self.assertNotIn(sentinel.encode(),result.stdout+result.stderr)
            self.assertEqual(json.loads(result.stdout)['reasonCode'],'EXACT_CAPTURE_MODE_REQUIRED')

    def test_delivered_capsule_hash_and_shell_syntax_are_exact(self):
        raw=(ROOT/'scripts/capture-m2-retained-mounts-20261101.py').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),'dfdedd2e038b524277d6db8ed9f00808798366e45552863b471f5d7de67014fa')
        subprocess.run(['/bin/bash','-n',str(ROOT/'scripts/launch-m2-retained-mount-capture-20261101.sh')],check=True,timeout=5)


if __name__=='__main__':unittest.main()
