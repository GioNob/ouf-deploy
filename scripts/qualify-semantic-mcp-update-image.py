#!/usr/bin/env python3
"""CI-only native image import of the already qualified unsigned candidate."""
import importlib.util,json,os,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
c=load(root/'tools/semantic_application_cutover/image_custody.py','custody')
p=load(root/'scripts/prepare-chatbot-semantic-mcp-update-review-20261016.py','preparation')
assert os.environ.get('OUF_CI_UNSIGNED_IMAGE_IMPORT')=='SYNTHETIC_RUNNER_ONLY'
base=Path(os.environ['MCP_REPROCESSING_PACKAGE_DIRECTORY'])/'package'
def native(*args):
 out=subprocess.check_output(['docker',*args],stderr=subprocess.DEVNULL,timeout=60)
 assert len(out)<=2097152
 return out
info=json.loads(native('info','--format','{{json .}}'))
containerd=info.get('Driver')=='overlayfs'and dict(info.get('DriverStatus')or[]).get('driver-type')=='io.containerd.snapshotter.v1'
assert containerd or info.get('Driver')=='overlay2'
with tempfile.TemporaryDirectory()as directory:
 path=Path(directory)/'candidate.tagless.tar'
 with (base/'image.docker.tar').open('rb')as src:
  audit=c.archive(src,p.TAR_SHA,p.IMAGE_SHA,p.SOURCE)
  with path.open('x+b')as output:derived=c.tagless_archive(src,output,audit,containerd=containerd)
 with path.open('rb')as src:audit=c.archive(src,derived['derivedArchiveSha256'],p.IMAGE_SHA,p.SOURCE)
 assert not audit['repositoryTags']
 if containerd:audit['nativeIdentity']=c.native_identity(audit)
 native('load','--input',str(path))
 observed=json.loads(native('image','inspect',c.runtime_image_id(audit)))
 assert len(observed)==1
 proof=c.loaded(audit,observed[0])
 print(json.dumps({'schema':'ouf.mcp-update-native-image-qualification.v1','nativeDriver':info['Driver'],
  'imageByteCustodyProven':proof['imageByteCustodyProven'],'sourceCommit':p.SOURCE,
  'configurationImageId':p.IMAGE_SHA,'nativeImageId':proof['imageId'],'targetOperations':0,
  'containerLifecycleOperations':0,'signatureIssued':False,'acceptanceGranted':False}))
