"""Exact Docker schema2 identity derived from authenticated config/layer bytes.

No Docker effects, journal writes or authority. Refuse compression substitutions;
only the same verified archive blobs can bind a native manifest identity here.
"""
import hashlib,json,tarfile
from image_custody import FIELDS,digest,hashed,require,LIMIT
MANIFEST='application/vnd.docker.distribution.manifest.v2+json'
CONFIG='application/vnd.docker.container.image.v1+json'
LAYER='application/vnd.docker.image.rootfs.diff.tar'
def descriptor(stream,audit):
 stream.seek(0);require(hashed(stream,LIMIT)[0]==audit['archiveSha256'],'AUTHENTICATED_ARCHIVE_BYTES_CHANGED');stream.seek(0)
 with tarfile.open(fileobj=stream,mode='r:') as tar:
  config=tar.getmember(audit['configMember'])
  layers=[]
  for name,proof in zip(audit['layerMembers'],audit['layers']):
   row=tar.getmember(name)
   with tar.extractfile(row) as src:magic=src.read(2)
   require(row.size==proof['archiveBytes'],'MANIFEST_LAYER_SIZE_DRIFT')
   layers.append({'mediaType':LAYER+('.gzip' if magic==b'\x1f\x8b' else ''),
    'digest':'sha256:'+proof['blobSha256'],'size':row.size})
  value={'schemaVersion':2,'mediaType':MANIFEST,
   'config':{'mediaType':CONFIG,'digest':audit['imageId'],'size':config.size},'layers':layers}
  # OCI Go struct ordering used by containerd archive importer. No sorted keys.
  raw=json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
 return {'mediaType':MANIFEST,'digest':'sha256:'+hashlib.sha256(raw).hexdigest(),'size':len(raw)}
def loaded(audit,expected,native):
 require(type(native) is dict and native.get('Id')==expected['digest']
  and native.get('Descriptor')==expected,'NATIVE_EXACT_MANIFEST_DESCRIPTOR_REQUIRED')
 require(native.get('Os')=='linux' and native.get('Architecture')=='amd64','EXACT_IMAGE_PLATFORM_REQUIRED')
 require(native.get('RootFS')=={'Type':'layers','Layers':[r['diffId'] for r in audit['layers']]},'NATIVE_ROOTFS_CUSTODY_DRIFT')
 require(type(native.get('Config')) is dict and all(native['Config'].get(k)==audit['imageConfig'].get(k) for k in FIELDS),'NATIVE_IMAGE_EXECUTION_CONFIG_DRIFT')
 require(not native.get('RepoTags'),'TAGLESS_IMAGE_IMPORT_REQUIRED')
 return {'schema':'ouf.native-manifest-image-byte-custody.v1','configImageId':audit['imageId'],
  'nativeEngineImageId':native['Id'],'manifestDescriptor':expected,'sourceCommit':audit['sourceCommit'],
  'archiveSha256':audit['archiveSha256'],'rootfsLayerCount':len(audit['layers']),
  'nativeConfigProjectionHash':digest({k:native['Config'].get(k) for k in FIELDS}),
  'nativeRootfsHash':digest(native['RootFS']),'imageByteCustodyProven':True,
  'completeContainerOciProven':False,'transportClosureProven':False,'targetApplyAuthorized':False}
