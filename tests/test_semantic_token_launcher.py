"""Release pins and actual private-copy wrapper with a synthetic child only."""
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SHELL=ROOT/'scripts/launch-chatbot-semantic-login-window-20261016.sh'

class Launcher(unittest.TestCase):
    def parsed(self):
        raw=SHELL.read_text();table=raw.split("<<'SOURCES'\n",1)[1].split('\nSOURCES',1)[0]
        body=raw.split("<<'PY' 2>&1 | tee \"$ouf_stage/run.log\"\n",1)[1].rsplit('\nPY',1)[0]
        assignments={}
        for node in ast.parse(body).body:
            if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
                try:assignments[node.targets[0].id]=ast.literal_eval(node.value)
                except (ValueError,TypeError):pass
        return raw,[line.split()for line in table.splitlines()],body,assignments
    def test_download_and_root_copy_pins_match_delivered_sources(self):
        raw,rows,body,values=self.parsed()
        self.assertEqual(len(rows),8)
        self.assertEqual({name:sha for path,sha,name in rows},values['expected'])
        for path,sha,name in rows:self.assertEqual(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(),sha,path)
        self.assertEqual(set(values['modules'].values()),set(values['expected'])-{'execute.py'})
        self.assertIn('?ref='+values['commit'],raw)
        self.assertLess(raw.index('ouf-gh-2.102.0'),raw.index('command -v gh'))
        self.assertLess(raw.index('sha256sum --check'),raw.index('sudo /usr/bin/python3'))
    def test_wrapper_copies_private_verified_code_and_rejects_tamper(self):
        _,rows,body,values=self.parsed()
        synthetic=b'''import json,os,stat,sys
from pathlib import Path
assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
assert sys.stdout.write_through, 'HUMAN login instructions must reach tee immediately'
d=Path(sys.argv[1]);package=json.loads((d/'package.json').read_bytes())
assert package['sourceCommit']==sys.argv[2]
for p in d.iterdir():
 s=p.stat();assert s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600
print('SYNTHETIC_CHILD_VERIFIED_COPY_ONLY')
'''
        with tempfile.TemporaryDirectory(dir=ROOT)as temporary:
            directory=Path(temporary);parent=directory/'private-parent';parent.mkdir(mode=0o700)
            stage=directory/'stage';stage.mkdir(mode=0o700)
            for path,sha,name in rows:(stage/name).write_bytes(synthetic if name=='execute.py'else(ROOT/path).read_bytes())
            script=body.replace("Path('/etc/ouf/deploy-snapshots')",'Path('+repr(str(parent))+')')
            script=script.replace(values['expected']['execute.py'],hashlib.sha256(synthetic).hexdigest())
            result=subprocess.run([sys.executable,'-I','-B','-S','-',str(stage)],input=script.encode(),
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            self.assertEqual(result.stdout,b'SYNTHETIC_CHILD_VERIFIED_COPY_ONLY\n')
            (stage/'supervisor.py').write_bytes(b'CHANGED')
            result=subprocess.run([sys.executable,'-I','-B','-S','-',str(stage)],input=script.encode(),
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
            self.assertNotEqual(result.returncode,0)
            self.assertNotIn(b'SYNTHETIC_CHILD_VERIFIED_COPY_ONLY',result.stdout)

if __name__=='__main__':unittest.main()
