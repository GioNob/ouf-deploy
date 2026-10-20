#!/usr/bin/env python3
"""Retained-host candidate custody only: no runtime authority or engine writes."""
import hashlib,json,os,signal,stat,sys,tempfile,traceback
from pathlib import Path
INPUT=Path('/etc/ouf/deploy-snapshots/chat-recovery-prepared-fi3s6kbv/prepared-inputs.json')
INPUT_HASH='67e36adf226b618d2d2a0749700a1d6b5118b7a8ea1849d011c95ee2f8f7e351'
REVIEW=Path('/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-chat-image-review-39080376709/image-review.json')
REVIEW_HASH='65d571a892489701f6037388270c9ec86d42cc3a22b89865bca9103b04b030d4'
def require(ok,reason):
 if not ok:raise ValueError(reason)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def pin(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def root_directory(path):
 for p in(path,*path.parents):
  s=p.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'ROOT_DIRECTORY_REQUIRED')
def open_input(path,limit,protected=False):
 require(path.is_absolute() and path.resolve()==path,'NO_LINK_INPUT_REQUIRED')
 if protected:root_directory(path.parent)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd)
  require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=limit,'BOUNDED_REGULAR_INPUT_REQUIRED')
  if protected:require(s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600,'PRIVATE_ROOT_INPUT_REQUIRED')
  return fd,s
 except BaseException:os.close(fd);raise
def read(path,expected,limit=8388608,protected=False):
 fd,before=open_input(path,limit,protected)
 try:
  chunks=[];size=0
  while True:
   block=os.read(fd,65536)
   if not block:break
   size+=len(block);require(size<=limit,'INPUT_BOUND');chunks.append(block)
  raw=b''.join(chunks)
  require(size==before.st_size and pin(before)==pin(os.fstat(fd)) and digest(raw)==expected,'INPUT_BYTES_CHANGED')
  return raw
 finally:os.close(fd)
def copy(source,target,expected):
 fd,before=open_input(source,2147483648)
 try:
  out=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  h=hashlib.sha256();size=0
  with os.fdopen(out,'wb')as dest:
   os.fchmod(dest.fileno(),0o600)
   while True:
    block=os.read(fd,1048576)
    if not block:break
    size+=len(block);require(size<=2147483648,'ARCHIVE_BOUND');h.update(block);dest.write(block)
   dest.flush();os.fsync(dest.fileno())
  require(size==before.st_size and pin(before)==pin(os.fstat(fd)) and h.hexdigest()==expected,'ARCHIVE_CHANGED')
 finally:os.close(fd)
def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_ROOT_NO_ARGUMENTS_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError()));signal.alarm(180)
 plan=json.loads(read(INPUT,INPUT_HASH,protected=True))
 require(plan['schema']=='ouf.chat-recovery-private-inputs.v1' and plan['readyForExecution'] is False and plan['runtimeAuthorityIssued'] is False,'EXACT_UNEXECUTED_INPUT_REQUIRED')
 review=json.loads(read(REVIEW,REVIEW_HASH))
 require(review['schema']=='ouf.chat-recovery-image-custody-review.v1' and set(review['candidates'])=={'udp','mcp'} and review['imagesImported']==0,'EXACT_IMAGE_REVIEW_REQUIRED')
 target=INPUT.parent/'candidate-custody';target.mkdir(mode=0o700)
 print(json.dumps({'check':'PRIVATE_CUSTODY_CONTEXT','contextPath':str(target),'runtimeMutations':0}),flush=True)
 candidates={}
 for module,row in review['candidates'].items():
  expected=plan['profile']['candidates'][module];audit=row['imageAudit']
  require(audit['imageId']==expected['imageId'] and audit['sourceCommit']==expected['sourceCommit'],'CANDIDATE_SCOPE_DRIFT')
  source=Path(row['imageArchive']['path'])
  require(source==REVIEW.parent/(module+'.tagless.tar'),'EXACT_REVIEWED_ARCHIVE_PATH_REQUIRED')
  path=target/(module+'.tagless.tar');copy(source,path,row['imageArchive']['sha256'])
  with path.open('rb')as stream:checked=CUSTODY['archive'](stream,row['imageArchive']['sha256'],expected['imageId'],expected['sourceCommit'])
  if review['containerd']:checked['nativeIdentity']=CUSTODY['native_identity'](checked)
  require(checked==audit and not checked['repositoryTags'] and CUSTODY['runtime_image_id'](checked)==row['nativeImageId'],'ROOT_IMAGE_READBACK_DRIFT')
  candidates[module]={**row,'imageArchive':{'path':str(path),'sha256':row['imageArchive']['sha256']}}
  print(json.dumps({'check':'ROOT_IMAGE_VERIFIED','module':module,'nativeImageId':row['nativeImageId'],'runtimeMutations':0}),flush=True)
 raw=json.dumps({'schema':'ouf.chat-recovery-root-candidates.v1','preparedInputsBinding':{'path':str(INPUT),'sha256':INPUT_HASH},
  'runnerReviewBinding':{'path':str(REVIEW),'sha256':REVIEW_HASH},'candidates':candidates,'containerd':review['containerd'],
  'packageRootCustodyProven':True,'readyForExecution':False,'runtimeAuthorityIssued':False,'imagesImported':0,'runtimeMutations':0},
  sort_keys=True,separators=(',',':')).encode()
 report=target/'review.json'
 fd=os.open(report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as dest:dest.write(raw);dest.flush();os.fsync(dest.fileno())
 fd=os.open(target,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
 require(read(report,digest(raw),protected=True)==raw,'ROOT_REVIEW_READBACK_FAILED')
 print(json.dumps({'check':'END','complete':True,'reviewPath':str(report),'reviewSha256':digest(raw),'packageRootCustodyProven':True,
  'imagesImported':0,'runtimeMutations':0,'readyForExecution':False,'runtimeAuthorityIssued':False,'backupPerformed':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':3},sort_keys=True),flush=True)

CUSTODY={'__name__':'qualified_image_custody'}
exec(compile("\"\"\"Docker archive and realized image byte custody; no effects or authority.\n\nCaller authenticates original publisher/ZIP and file custody separately.\nArchive/file-digest or image-inspection equality never grants installation.\n\"\"\"\nimport gzip,hashlib,json,re,tarfile\nfrom pathlib import PurePosixPath\n\nLIMIT=2147483648\nFIELDS=('User','Entrypoint','Cmd','Env','WorkingDir','Labels','Volumes','ExposedPorts','StopSignal','Healthcheck','Shell')\n\nclass ImageCustodyDenied(ValueError):pass\n\ndef require(ok, reason):\n    if not ok:raise ImageCustodyDenied(reason)\n\ndef encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()\ndef digest(value):return hashlib.sha256(encoded(value)).hexdigest()\ndef hashed(stream,limit):\n    h=hashlib.sha256();count=0\n    while True:\n        raw=stream.read(min(1048576,limit-count+1))\n        if not raw:break\n        count+=len(raw);require(count<=limit,'BOUNDED_IMAGE_BYTES_REQUIRED');h.update(raw)\n    return h.hexdigest(),count\n\ndef parsed(raw):\n    def unique(rows):\n        result={}\n        for k,v in rows:\n            require(k not in result,'DUPLICATE_IMAGE_METADATA_KEY');result[k]=v\n        return result\n    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:require(False,'FINITE_IMAGE_METADATA_REQUIRED'))\n\ndef archive(stream,expected_tar_sha256,expected_image,expected_source):\n    require(re.fullmatch('[0-9a-f]{64}',expected_tar_sha256) is not None\n            and re.fullmatch('sha256:[0-9a-f]{64}',expected_image) is not None\n            and re.fullmatch('[0-9a-f]{40}',expected_source) is not None,'EXACT_IMAGE_BINDINGS_REQUIRED')\n    stream.seek(0);require(hashed(stream,LIMIT)[0]==expected_tar_sha256,'AUTHENTICATED_ARCHIVE_BYTES_CHANGED');stream.seek(0)\n    with tarfile.open(fileobj=stream,mode='r:') as tar:\n        members={}\n        for row in tar:\n            path=PurePosixPath(row.name)\n            require(not path.is_absolute() and '..' not in path.parts and str(path)==row.name\n                    and row.name not in members and len(members)<512,'SAFE_UNIQUE_IMAGE_ARCHIVE_REQUIRED')\n            require(row.isfile() or row.isdir(),'IMAGE_ARCHIVE_LINK_OR_SPECIAL_ENTRY_DENIED')\n            require(0<=row.size<=LIMIT,'BOUNDED_IMAGE_MEMBER_REQUIRED');members[row.name]=row\n        def member(name):\n            require(type(name) is str and name in members and members[name].isfile(),'EXACT_IMAGE_MEMBER_REQUIRED')\n            return members[name]\n        def small(name,limit):\n            row=member(name);require(row.size<=limit,'BOUNDED_IMAGE_METADATA_REQUIRED')\n            with tar.extractfile(row) as src:return src.read(limit+1)\n        manifest=parsed(small('manifest.json',131072))\n        require(type(manifest) is list and len(manifest)==1 and type(manifest[0]) is dict,'ONE_IMAGE_ARCHIVE_REQUIRED')\n        image=manifest[0];raw=small(image['Config'],2097152)\n        require('sha256:'+hashlib.sha256(raw).hexdigest()==expected_image,'IMAGE_CONFIG_DIGEST_DRIFT')\n        config=parsed(raw)\n        require(config.get('os')=='linux' and config.get('architecture')=='amd64','EXACT_IMAGE_PLATFORM_REQUIRED')\n        require(type(config.get('config')) is dict and config['config'].get('Labels',{}).get('org.opencontainers.image.revision')==expected_source,'IMAGE_SOURCE_LABEL_DRIFT')\n        layers=image.get('Layers');root=config.get('rootfs',{})\n        require(root.get('type')=='layers' and type(layers) is list and 1<=len(layers)<=64\n                and len(layers)==len(set(layers)) and type(root.get('diff_ids')) is list\n                and len(root['diff_ids'])==len(layers),'EXACT_ROOTFS_LAYER_SET_REQUIRED')\n        observations=[];total=0\n        for name,expected in zip(layers,root['diff_ids']):\n            row=member(name)\n            with tar.extractfile(row) as src:blob,size=hashed(src,LIMIT)\n            if name.startswith('blobs/sha256/'):\n                require(name=='blobs/sha256/'+blob,'CONTENT_ADDRESSED_LAYER_DRIFT')\n            with tar.extractfile(row) as src:\n                magic=src.read(2);src.seek(0)\n                if magic==b'\\x1f\\x8b':\n                    with gzip.GzipFile(fileobj=src) as expanded:actual,expanded_size=hashed(expanded,LIMIT-total)\n                else:actual,expanded_size=hashed(src,LIMIT-total)\n            total+=expanded_size\n            require(expected=='sha256:'+actual,'ROOTFS_LAYER_BYTES_DRIFT')\n            observations.append({'blobSha256':blob,'diffId':expected,'archiveBytes':size,'expandedBytes':expanded_size})\n        tags=image.get('RepoTags')\n        require(tags is None or type(tags) is list and len(tags)<=16\n                and all(type(x) is str and 0<len(x)<=256 for x in tags),'BOUNDED_IMAGE_TAGS_REQUIRED')\n        return {'schema':'ouf.image-archive-byte-custody.v1','imageId':expected_image,\n                'sourceCommit':expected_source,'archiveSha256':expected_tar_sha256,\n                'configSha256':expected_image[7:],'configBytes':len(raw),'layers':observations,'platform':'linux/amd64',\n                'repositoryTags':tags or [],'imageConfig':config['config'],\n                'configMember':image['Config'],'layerMembers':layers,\n                'archiveByteCustodyProven':True,'targetApplyAuthorized':False}\n\ndef manifest_bytes(audit):\n    \"\"\"Exact Docker schema2 descriptors, with unchanged config/layer bytes.\"\"\"\n    require(audit.get('imageId')=='sha256:'+audit['configSha256']\n            and type(audit.get('configBytes')) is int and 0<audit['configBytes']<=2097152,\n            'EXACT_CONFIGURATION_BYTE_IDENTITY_REQUIRED')\n    descriptor=lambda media,digest,size:{'mediaType':media,'digest':digest,'size':size}\n    layers=[]\n    for row in audit['layers']:\n        plain='sha256:'+row['blobSha256']==row['diffId']\n        layers.append(descriptor('application/vnd.docker.image.rootfs.diff.tar'+('' if plain else '.gzip'),\n            'sha256:'+row['blobSha256'],row['archiveBytes']))\n    value={'schemaVersion':2,'mediaType':'application/vnd.docker.distribution.manifest.v2+json',\n        'config':descriptor('application/vnd.docker.container.image.v1+json',audit['imageId'],audit['configBytes']),\n        'layers':layers}\n    # Descriptor order matches the image-spec encoding; no native metadata is\n    # normalized or guessed. This exact byte string is included in the archive.\n    return json.dumps(value,separators=(',',':'),allow_nan=False).encode()\n\ndef native_identity(audit):\n    raw=manifest_bytes(audit)\n    return {'profile':'ouf.config-and-native-manifest-identity.v1',\n        'configurationImageId':audit['imageId'],'nativeImageId':'sha256:'+hashlib.sha256(raw).hexdigest(),\n        'manifestBytes':len(raw),'platform':'linux/amd64'}\n\ndef runtime_image_id(audit):\n    binding=audit.get('nativeIdentity')\n    if binding is None:return audit['imageId']\n    require(binding==native_identity(audit),'EXACT_NATIVE_MANIFEST_IDENTITY_REQUIRED')\n    return binding['nativeImageId']\n\ndef unbound_audit(audit):return {k:v for k,v in audit.items() if k!='nativeIdentity'}\n\ndef tagless_archive(source,output,audit,*,containerd=False):\n    \"\"\"Re-envelope exact authenticated config/layers without repository tags.\n\n    No image rebuild, new config, layer or publisher signature. Caller reaudits\n    returned archive hash/image/source before import; original provenance is\n    retained separately. Exclude unrelated OCI metadata/old tag descriptors.\n    \"\"\"\n    source.seek(0);require(hashed(source,LIMIT)[0]==audit['archiveSha256'],'AUTHENTICATED_ARCHIVE_BYTES_CHANGED');source.seek(0)\n    output.seek(0);output.truncate()\n    with tarfile.open(fileobj=source,mode='r:') as original,tarfile.open(fileobj=output,mode='w') as target:\n        import io\n        manifest=[{'Config':audit['configMember'],'RepoTags':None,'Layers':audit['layerMembers']}]\n        raw=encoded(manifest);row=tarfile.TarInfo('manifest.json');row.size=len(raw);row.mode=0o600\n        target.addfile(row,io.BytesIO(raw))\n        if containerd:\n            content=manifest_bytes(audit);binding=native_identity(audit)\n            entries={'oci-layout':encoded({'imageLayoutVersion':'1.0.0'}),\n                'index.json':encoded({'schemaVersion':2,'manifests':[{\n                    'mediaType':'application/vnd.docker.distribution.manifest.v2+json',\n                    'digest':binding['nativeImageId'],'size':len(content),\n                    'platform':{'architecture':'amd64','os':'linux'}}]}),\n                'blobs/sha256/'+binding['nativeImageId'][7:]:content}\n            require(not set(entries)&{audit['configMember'],*audit['layerMembers']},'NATIVE_MANIFEST_MEMBER_COLLISION')\n            # An explicit OCI index prevents the legacy importer from choosing\n            # alternative compressed layer descriptors from its local cache.\n            for name,body in entries.items():\n                row=tarfile.TarInfo(name);row.size=len(body);row.mode=0o600\n                target.addfile(row,io.BytesIO(body))\n        copies={name:name for name in [audit['configMember'],*audit['layerMembers']]}\n        if containerd:\n            copies['blobs/sha256/'+audit['configSha256']]=audit['configMember']\n            for name,layer in zip(audit['layerMembers'],audit['layers']):\n                copies['blobs/sha256/'+layer['blobSha256']]=name\n        for name,source_name in copies.items():\n            old=original.getmember(source_name);require(old.isfile(),'EXACT_IMAGE_MEMBER_REQUIRED')\n            row=tarfile.TarInfo(name);row.size=old.size;row.mode=0o600\n            with original.extractfile(old) as content:target.addfile(row,content)\n    output.flush();output.seek(0);result,size=hashed(output,LIMIT);output.seek(0)\n    return {'originalArchiveSha256':audit['archiveSha256'],'derivedArchiveSha256':result,\n            'archiveBytes':size,'imageRebuilt':False,'newSignatureIssued':False}\n\ndef loaded(audit,native):\n    expected=runtime_image_id(audit)\n    require(type(native) is dict and native.get('Id')==expected\n            and native.get('Os')=='linux' and native.get('Architecture')=='amd64','NATIVE_IMAGE_IDENTITY_DRIFT')\n    require(native.get('RootFS')=={'Type':'layers','Layers':[r['diffId'] for r in audit['layers']]},'NATIVE_ROOTFS_CUSTODY_DRIFT')\n    require(type(native.get('Config')) is dict and all(native['Config'].get(k)==audit['imageConfig'].get(k) for k in FIELDS),'NATIVE_IMAGE_EXECUTION_CONFIG_DRIFT')\n    return {'schema':'ouf.loaded-image-byte-custody.v1','imageId':expected,\n            'sourceCommit':audit['sourceCommit'],'archiveSha256':audit['archiveSha256'],\n            'rootfsLayerCount':len(audit['layers']),'nativeConfigProjectionHash':digest({k:native['Config'].get(k) for k in FIELDS}),\n            'nativeRootfsHash':digest(native['RootFS']),'imageByteCustodyProven':True,\n            'completeContainerOciProven':False,'transportClosureProven':False,'targetApplyAuthorized':False}\n",'<qualified-image-custody>','exec'),CUSTODY)

if __name__=='__main__':
 try:main()
 except Exception as error:
  print(json.dumps({'check':'STOP','errorClass':type(error).__name__,'frames':[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno} for f in traceback.extract_tb(error.__traceback__)[-6:]],'exceptionMessagePrinted':False,'runtimeMutations':0,'readyForExecution':False,'automaticRetry':False}));sys.exit(2)
