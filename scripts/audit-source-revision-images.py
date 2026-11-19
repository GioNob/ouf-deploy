#!/usr/bin/env python3
"""Audit and re-envelope delivered images without importing or starting them."""
import hashlib,json,os,runpy,subprocess,sys
from pathlib import Path,PurePosixPath
import re
def require(ok,reason):
 if not ok:raise ValueError(reason)
def sha(path):
 h=hashlib.sha256()
 with path.open('rb')as source:
  for block in iter(lambda:source.read(1048576),b''):h.update(block)
 return h.hexdigest()
def main(root,output,manifest_sha,build_run):
 root=Path(root);output=Path(output)
 require(root.is_dir() and not root.is_symlink() and all(not p.is_symlink()for p in root.parents),'PACKAGE_ROOT_REQUIRED')
 require(sha(root/'SHA256SUMS')==manifest_sha,'QUALIFIED_MANIFEST_REQUIRED')
 hashes={}
 for line in(root/'SHA256SUMS').read_text().splitlines():
  digest,name=line.split('  ',1)
  relative=PurePosixPath(name)
  require(re.fullmatch('[0-9a-f]{64}',digest) and str(relative)==name and not relative.is_absolute() and '..' not in relative.parts and name not in hashes,'SAFE_UNIQUE_PACKAGE_MEMBERS_REQUIRED');hashes[name]=digest
 def member(name):
  path=root/name
  require(name in hashes and path.is_file() and all(not p.is_symlink()for p in(path,*path.parents)) and sha(path)==hashes[name],'CANDIDATE_BYTES_CHANGED')
  return path
 require(output.parent==root.parent and output.name.startswith('ouf-source-revision-image-review-') and not output.exists(),'NEW_PRIVATE_OUTPUT_REQUIRED')
 result=subprocess.run(['/usr/bin/docker','info','--format','{"driver":{{json .Driver}},"status":{{json .DriverStatus}}}'],
  capture_output=True,timeout=10,env={'PATH':'/usr/bin:/bin','DOCKER_HOST':'unix:///var/run/docker.sock','DOCKER_API_VERSION':'1.44'})
 require(result.returncode==0 and len(result.stdout)<8192,'ENGINE_STORAGE_READ_UNPROVEN')
 info=json.loads(result.stdout);containerd=info['driver']=='overlayfs' and dict(info['status'] or []).get('driver-type')=='io.containerd.snapshotter.v1'
 require(containerd or info['driver']=='overlay2','UNQUALIFIED_IMAGE_STORAGE_DRIVER')
 custody=runpy.run_path(str(Path(__file__).resolve().parents[1]/'tools/linked_property_rollout/image_custody.py'))
 output.mkdir(mode=0o700);audits={}
 for module in('onboarding','mcp'):
  prefix='parts/source-revision-part-'+module+'-'+build_run+'/'
  meta=json.loads(member(prefix+'candidate-manifest.json').read_bytes())
  original=member(prefix+'image.docker.tar')
  derived=output/(module+'.tagless.tar')
  with original.open('rb')as source:
   audit=custody['archive'](source,hashes[prefix+'image.docker.tar'],meta['imageId'],meta['sourceCommit'])
   with derived.open('x+b')as dest:
    os.chmod(derived,0o600)
    converted=custody['tagless_archive'](source,dest,audit,containerd=containerd)
    dest.flush();os.fsync(dest.fileno())
  with derived.open('rb')as source:
   checked=custody['archive'](source,converted['derivedArchiveSha256'],meta['imageId'],meta['sourceCommit'])
  require(not checked['repositoryTags'],'TAGLESS_IMAGE_REQUIRED')
  if containerd:checked['nativeIdentity']=custody['native_identity'](checked)
  audits[module]={'imageAudit':checked,'imageArchive':{'path':str(derived),'sha256':converted['derivedArchiveSha256']},
    'nativeImageId':custody['runtime_image_id'](checked)}
  print(json.dumps({'check':'IMAGE_VERIFIED','module':module,'nativeImageId':audits[module]['nativeImageId'],
   'sourceCommit':meta['sourceCommit'],'layerCount':len(checked['layers']),'runtimeMutations':0},sort_keys=True),flush=True)
 report={'schema':'ouf.source-revision-image-custody-review.v1','containerd':containerd,'candidates':audits,
  'rootCustodyProven':False,'runtimeMutations':0,'imagesImported':0,'imageRebuilt':False,'readyForExecution':False}
 raw=json.dumps(report,sort_keys=True,separators=(',',':')).encode()
 with(output/'image-review.json').open('xb')as dest:
  os.chmod(output/'image-review.json',0o600);dest.write(raw);dest.flush();os.fsync(dest.fileno())
 print(json.dumps({'check':'END','complete':True,'imageReviewPath':str(output/'image-review.json'),'imageReviewSha256':hashlib.sha256(raw).hexdigest(),
  'rootCustodyProven':False,'runtimeMutations':0,'imagesImported':0,'completedTechnicalPhases':8,'functionalMilestonesProven':4},sort_keys=True))
if __name__=='__main__':
 try:
  require(len(sys.argv)==5,'EXACT_ARGUMENTS_REQUIRED');main(*sys.argv[1:])
 except Exception as error:
  print(json.dumps({'check':'STOP','errorClass':type(error).__name__,'exceptionMessagePrinted':False,'runtimeMutations':0}));sys.exit(1)
