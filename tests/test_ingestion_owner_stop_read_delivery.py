import ast,hashlib,importlib.util,re,subprocess,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
reader=HERE/'read_stop.py';launcher=HERE/'launch_read.sh'
if not reader.exists():
 reader=ROOT/'scripts/read-ingestion-owner-reference-stop-20261019.py';launcher=ROOT/'scripts/launch-ingestion-owner-reference-stop-read-20261019.sh'
class Delivery(unittest.TestCase):
 def test_reader_bytes_are_pinned_by_git_blob_and_sha256_before_and_after_sudo(self):
  raw=reader.read_bytes();script=launcher.read_text();sha=hashlib.sha256(raw).hexdigest()
  blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
  self.assertIn('/git/blobs/'+blob,script);self.assertEqual(script.count(sha),2)
  self.assertLess(script.index('sha256sum -c -'),script.index('sudo /usr/bin/python3'))
  self.assertLess(script.index('$HOME/ouf-gh-2.102.0.PNoFbF'),script.index('command -v gh'))
  subprocess.run(['bash','-n',str(launcher)],check=True)
  wrapper=script.split("<<'OUF_READ' | tee",1)[1].split('\n',1)[1].split('\nOUF_READ',1)[0]
  compile(wrapper,'<root-verifying-reader-wrapper>','exec')
 def test_reader_has_no_runtime_imports_network_process_or_write_primitives(self):
  tree=ast.parse(reader.read_bytes());imports=set()
  for node in ast.walk(tree):
   if isinstance(node,ast.Import):imports.update(alias.name for alias in node.names)
   elif isinstance(node,ast.ImportFrom):imports.add(node.module)
   if isinstance(node,ast.Call):
    name=node.func.attr if isinstance(node.func,ast.Attribute)else node.func.id if isinstance(node.func,ast.Name)else''
    self.assertNotIn(name,{'exec','eval','compile','write','write_bytes','write_text','unlink','rename','replace','mkdir','system','Popen','urlopen'})
  self.assertEqual(imports,{'base64','hashlib','json','os','re','signal','stat','sys','pathlib'})
  self.assertIn('O_RDONLY',reader.read_text());self.assertNotIn('O_WRONLY',reader.read_text())
if __name__=='__main__':unittest.main()
