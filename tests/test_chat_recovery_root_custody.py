import contextlib,hashlib,importlib.util,io,json,os,signal,sys,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('custody',Path(__file__).resolve().parents[1]/'scripts/prepare-chat-recovery-root-custody.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class RootCustody(unittest.TestCase):
 def fixture(self,root):
  inputs=root/'inputs';inputs.mkdir(mode=0o700);runner=root/'runner';runner.mkdir(mode=0o700)
  candidates={};expected={}
  for module in('udp','mcp'):
   layer=io.BytesIO()
   with tarfile.open(fileobj=layer,mode='w'):pass
   rawlayer=layer.getvalue();commit=('a'if module=='udp'else'b')*40
   config=json.dumps({'os':'linux','architecture':'amd64','config':{'Labels':{'org.opencontainers.image.revision':commit}},
    'rootfs':{'type':'layers','diff_ids':['sha256:'+p.digest(rawlayer)]}}).encode()
   image='sha256:'+p.digest(config);path=runner/(module+'.tagless.tar')
   with tarfile.open(path,'w')as archive:
    for name,raw in {'config.json':config,'layer.tar':rawlayer,'manifest.json':json.dumps([{'Config':'config.json','RepoTags':None,'Layers':['layer.tar']}]).encode()}.items():
     row=tarfile.TarInfo(name);row.size=len(raw);archive.addfile(row,io.BytesIO(raw))
   with path.open('rb')as stream:audit=p.CUSTODY['archive'](stream,p.digest(path.read_bytes()),image,commit)
   candidates[module]={'imageAudit':audit,'imageArchive':{'path':str(path),'sha256':p.digest(path.read_bytes())},'nativeImageId':image}
   expected[module]={'imageId':image,'sourceCommit':commit}
  inp=inputs/'prepared-inputs.json'
  inp.write_text(json.dumps({'schema':'ouf.chat-recovery-private-inputs.v1','readyForExecution':False,'runtimeAuthorityIssued':False,'profile':{'candidates':expected}}));inp.chmod(0o600)
  review=runner/'image-review.json'
  review.write_text(json.dumps({'schema':'ouf.chat-recovery-image-custody-review.v1','candidates':candidates,'containerd':False,'imagesImported':0}))
  return inp,review
 def exercise(self,tamper=False):
  with tempfile.TemporaryDirectory(dir='/root')as temp:
   root=Path(temp);root.chmod(0o700);inp,review=self.fixture(root)
   if tamper:(review.parent/'udp.tagless.tar').write_bytes(b'changed')
   out=io.StringIO()
   with patch.object(p,'INPUT',inp),patch.object(p,'INPUT_HASH',p.digest(inp.read_bytes())),patch.object(p,'REVIEW',review),patch.object(p,'REVIEW_HASH',p.digest(review.read_bytes())),patch.object(sys,'argv',['fixture']),contextlib.redirect_stdout(out):
    try:
     if tamper:
      with self.assertRaises(ValueError):p.main()
     else:p.main()
    finally:signal.alarm(0)
   report=inp.parent/'candidate-custody/review.json'
   if tamper:self.assertFalse(report.exists())
   else:
    value=json.loads(report.read_bytes())
    self.assertTrue(value['packageRootCustodyProven']);self.assertFalse(value['readyForExecution'])
    self.assertEqual(report.stat().st_mode&0o777,0o600)
    self.assertEqual(json.loads(out.getvalue().splitlines()[-1])['reviewSha256'],p.digest(report.read_bytes()))
    for module,row in value['candidates'].items():self.assertEqual(Path(row['imageArchive']['path']).read_bytes(),(review.parent/(module+'.tagless.tar')).read_bytes())
    with self.assertRaises(FileExistsError):(inp.parent/'candidate-custody').mkdir()
 def test_whole_copy_and_deep_image_readback(self):self.exercise()
 def test_changed_archive_never_publishes_review(self):self.exercise(True)
 def test_symlink_input_rejected(self):
  with tempfile.TemporaryDirectory(dir='/root')as temp:
   root=Path(temp);file=root/'file';file.write_bytes(b'x');link=root/'link';link.symlink_to(file)
   with self.assertRaises(ValueError):p.read(link,p.digest(b'x'))
 def test_existing_target_never_overwritten(self):
  with tempfile.TemporaryDirectory(dir='/root')as temp:
   root=Path(temp);source=root/'source';source.write_bytes(b'new');target=root/'target';target.write_bytes(b'old')
   with self.assertRaises(FileExistsError):p.copy(source,target,p.digest(b'new'))
   self.assertEqual(target.read_bytes(),b'old')
if __name__=='__main__':unittest.main()
