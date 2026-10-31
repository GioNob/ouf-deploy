"""Docker archive and realized image byte custody; no effects or authority.

Caller authenticates original publisher/ZIP and file custody separately.
Archive/file-digest or image-inspection equality never grants installation.
"""
import gzip,hashlib,json,re,tarfile
from pathlib import PurePosixPath

LIMIT=2147483648
FIELDS=('User','Entrypoint','Cmd','Env','WorkingDir','Labels','Volumes','ExposedPorts','StopSignal','Healthcheck','Shell')

class ImageCustodyDenied(ValueError):pass

def require(ok, reason):
    if not ok:raise ImageCustodyDenied(reason)

def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()
def hashed(stream,limit):
    h=hashlib.sha256();count=0
    while True:
        raw=stream.read(min(1048576,limit-count+1))
        if not raw:break
        count+=len(raw);require(count<=limit,'BOUNDED_IMAGE_BYTES_REQUIRED');h.update(raw)
    return h.hexdigest(),count

def parsed(raw):
    def unique(rows):
        result={}
        for k,v in rows:
            require(k not in result,'DUPLICATE_IMAGE_METADATA_KEY');result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:require(False,'FINITE_IMAGE_METADATA_REQUIRED'))

def archive(stream,expected_tar_sha256,expected_image,expected_source,*,ci_source_binding=None):
    require(re.fullmatch('[0-9a-f]{64}',expected_tar_sha256) is not None
            and re.fullmatch('sha256:[0-9a-f]{64}',expected_image) is not None
            and re.fullmatch('[0-9a-f]{40}',expected_source) is not None,'EXACT_IMAGE_BINDINGS_REQUIRED')
    stream.seek(0);require(hashed(stream,LIMIT)[0]==expected_tar_sha256,'AUTHENTICATED_ARCHIVE_BYTES_CHANGED');stream.seek(0)
    with tarfile.open(fileobj=stream,mode='r:') as tar:
        members={}
        for row in tar:
            path=PurePosixPath(row.name)
            require(not path.is_absolute() and '..' not in path.parts and str(path)==row.name
                    and row.name not in members and len(members)<512,'SAFE_UNIQUE_IMAGE_ARCHIVE_REQUIRED')
            require(row.isfile() or row.isdir(),'IMAGE_ARCHIVE_LINK_OR_SPECIAL_ENTRY_DENIED')
            require(0<=row.size<=LIMIT,'BOUNDED_IMAGE_MEMBER_REQUIRED');members[row.name]=row
        def member(name):
            require(type(name) is str and name in members and members[name].isfile(),'EXACT_IMAGE_MEMBER_REQUIRED')
            return members[name]
        def small(name,limit):
            row=member(name);require(row.size<=limit,'BOUNDED_IMAGE_METADATA_REQUIRED')
            with tar.extractfile(row) as src:return src.read(limit+1)
        manifest=parsed(small('manifest.json',131072))
        require(type(manifest) is list and len(manifest)==1 and type(manifest[0]) is dict,'ONE_IMAGE_ARCHIVE_REQUIRED')
        image=manifest[0];raw=small(image['Config'],2097152)
        require('sha256:'+hashlib.sha256(raw).hexdigest()==expected_image,'IMAGE_CONFIG_DIGEST_DRIFT')
        config=parsed(raw)
        require(config.get('os')=='linux' and config.get('architecture')=='amd64','EXACT_IMAGE_PLATFORM_REQUIRED')
        require(type(config.get('config')) is dict,'TYPED_IMAGE_CONFIG_REQUIRED')
        labels=config['config'].get('Labels')or{};require(type(labels)is dict,'TYPED_IMAGE_LABELS_REQUIRED')
        revision=labels.get('org.opencontainers.image.revision')
        if revision is not None:
            require(revision==expected_source,'IMAGE_SOURCE_LABEL_DRIFT')
        else:
            require(type(ci_source_binding)is dict and set(ci_source_binding)=={'schema','sourceCommit','imageId','compressedArchiveSha256','stagedReceiptHash','frozenPlanHash'}
                and ci_source_binding['schema']=='ouf.acquisition-image-source-by-qualified-ci-manifest.v1'
                and ci_source_binding['sourceCommit']==expected_source and ci_source_binding['imageId']==expected_image
                and all(type(ci_source_binding[k])is str and re.fullmatch('[a-f0-9]{64}',ci_source_binding[k])for k in('compressedArchiveSha256','stagedReceiptHash','frozenPlanHash')),
                'EXPLICIT_QUALIFIED_CI_SOURCE_BINDING_REQUIRED')
        layers=image.get('Layers');root=config.get('rootfs',{})
        require(root.get('type')=='layers' and type(layers) is list and 1<=len(layers)<=64
                and len(layers)==len(set(layers)) and type(root.get('diff_ids')) is list
                and len(root['diff_ids'])==len(layers),'EXACT_ROOTFS_LAYER_SET_REQUIRED')
        observations=[];total=0
        for name,expected in zip(layers,root['diff_ids']):
            row=member(name)
            with tar.extractfile(row) as src:blob,size=hashed(src,LIMIT)
            if name.startswith('blobs/sha256/'):
                require(name=='blobs/sha256/'+blob,'CONTENT_ADDRESSED_LAYER_DRIFT')
            with tar.extractfile(row) as src:
                magic=src.read(2);src.seek(0)
                if magic==b'\x1f\x8b':
                    with gzip.GzipFile(fileobj=src) as expanded:actual,expanded_size=hashed(expanded,LIMIT-total)
                else:actual,expanded_size=hashed(src,LIMIT-total)
            total+=expanded_size
            require(expected=='sha256:'+actual,'ROOTFS_LAYER_BYTES_DRIFT')
            observations.append({'blobSha256':blob,'diffId':expected,'archiveBytes':size,'expandedBytes':expanded_size})
        tags=image.get('RepoTags')
        require(tags is None or type(tags) is list and len(tags)<=16
                and all(type(x) is str and 0<len(x)<=256 for x in tags),'BOUNDED_IMAGE_TAGS_REQUIRED')
        return {'schema':'ouf.image-archive-byte-custody.v1','imageId':expected_image,
                'sourceCommit':expected_source,'archiveSha256':expected_tar_sha256,
                'configSha256':expected_image[7:],'configBytes':len(raw),'layers':observations,'platform':'linux/amd64',
                'repositoryTags':tags or [],'imageConfig':config['config'],
                'configMember':image['Config'],'layerMembers':layers,
                'archiveByteCustodyProven':True,'sourceBindingProfile':'OCI_REVISION_LABEL'if revision is not None else'QUALIFIED_CI_MANIFEST','qualifiedCiSourceBinding':ci_source_binding if revision is None else None,'targetApplyAuthorized':False}

def manifest_bytes(audit):
    """Exact Docker schema2 descriptors, with unchanged config/layer bytes."""
    require(audit.get('imageId')=='sha256:'+audit['configSha256']
            and type(audit.get('configBytes')) is int and 0<audit['configBytes']<=2097152,
            'EXACT_CONFIGURATION_BYTE_IDENTITY_REQUIRED')
    descriptor=lambda media,digest,size:{'mediaType':media,'digest':digest,'size':size}
    layers=[]
    for row in audit['layers']:
        plain='sha256:'+row['blobSha256']==row['diffId']
        layers.append(descriptor('application/vnd.docker.image.rootfs.diff.tar'+('' if plain else '.gzip'),
            'sha256:'+row['blobSha256'],row['archiveBytes']))
    value={'schemaVersion':2,'mediaType':'application/vnd.docker.distribution.manifest.v2+json',
        'config':descriptor('application/vnd.docker.container.image.v1+json',audit['imageId'],audit['configBytes']),
        'layers':layers}
    # Descriptor order matches the image-spec encoding; no native metadata is
    # normalized or guessed. This exact byte string is included in the archive.
    return json.dumps(value,separators=(',',':'),allow_nan=False).encode()

def native_identity(audit):
    raw=manifest_bytes(audit)
    return {'profile':'ouf.config-and-native-manifest-identity.v1',
        'configurationImageId':audit['imageId'],'nativeImageId':'sha256:'+hashlib.sha256(raw).hexdigest(),
        'manifestBytes':len(raw),'platform':'linux/amd64'}

def runtime_image_id(audit):
    binding=audit.get('nativeIdentity')
    if binding is None:return audit['imageId']
    require(binding==native_identity(audit),'EXACT_NATIVE_MANIFEST_IDENTITY_REQUIRED')
    return binding['nativeImageId']

def unbound_audit(audit):return {k:v for k,v in audit.items() if k!='nativeIdentity'}

def tagless_archive(source,output,audit,*,containerd=False):
    """Re-envelope exact authenticated config/layers without repository tags.

    No image rebuild, new config, layer or publisher signature. Caller reaudits
    returned archive hash/image/source before import; original provenance is
    retained separately. Exclude unrelated OCI metadata/old tag descriptors.
    """
    source.seek(0);require(hashed(source,LIMIT)[0]==audit['archiveSha256'],'AUTHENTICATED_ARCHIVE_BYTES_CHANGED');source.seek(0)
    output.seek(0);output.truncate()
    with tarfile.open(fileobj=source,mode='r:') as original,tarfile.open(fileobj=output,mode='w') as target:
        import io
        manifest=[{'Config':audit['configMember'],'RepoTags':None,'Layers':audit['layerMembers']}]
        raw=encoded(manifest);row=tarfile.TarInfo('manifest.json');row.size=len(raw);row.mode=0o600
        target.addfile(row,io.BytesIO(raw))
        if containerd:
            content=manifest_bytes(audit);binding=native_identity(audit)
            entries={'oci-layout':encoded({'imageLayoutVersion':'1.0.0'}),
                'index.json':encoded({'schemaVersion':2,'manifests':[{
                    'mediaType':'application/vnd.docker.distribution.manifest.v2+json',
                    'digest':binding['nativeImageId'],'size':len(content),
                    'platform':{'architecture':'amd64','os':'linux'}}]}),
                'blobs/sha256/'+binding['nativeImageId'][7:]:content}
            require(not set(entries)&{audit['configMember'],*audit['layerMembers']},'NATIVE_MANIFEST_MEMBER_COLLISION')
            # An explicit OCI index prevents the legacy importer from choosing
            # alternative compressed layer descriptors from its local cache.
            for name,body in entries.items():
                row=tarfile.TarInfo(name);row.size=len(body);row.mode=0o600
                target.addfile(row,io.BytesIO(body))
        copies={name:name for name in [audit['configMember'],*audit['layerMembers']]}
        if containerd:
            copies['blobs/sha256/'+audit['configSha256']]=audit['configMember']
            for name,layer in zip(audit['layerMembers'],audit['layers']):
                copies['blobs/sha256/'+layer['blobSha256']]=name
        for name,source_name in copies.items():
            old=original.getmember(source_name);require(old.isfile(),'EXACT_IMAGE_MEMBER_REQUIRED')
            row=tarfile.TarInfo(name);row.size=old.size;row.mode=0o600
            with original.extractfile(old) as content:target.addfile(row,content)
    output.flush();output.seek(0);result,size=hashed(output,LIMIT);output.seek(0)
    return {'originalArchiveSha256':audit['archiveSha256'],'derivedArchiveSha256':result,
            'archiveBytes':size,'imageRebuilt':False,'newSignatureIssued':False}

def loaded(audit,native):
    expected=runtime_image_id(audit)
    require(type(native) is dict and native.get('Id')==expected
            and native.get('Os')=='linux' and native.get('Architecture')=='amd64','NATIVE_IMAGE_IDENTITY_DRIFT')
    require(native.get('RootFS')=={'Type':'layers','Layers':[r['diffId'] for r in audit['layers']]},'NATIVE_ROOTFS_CUSTODY_DRIFT')
    require(type(native.get('Config')) is dict and all(native['Config'].get(k)==audit['imageConfig'].get(k) for k in FIELDS),'NATIVE_IMAGE_EXECUTION_CONFIG_DRIFT')
    return {'schema':'ouf.loaded-image-byte-custody.v1','imageId':expected,
            'sourceCommit':audit['sourceCommit'],'archiveSha256':audit['archiveSha256'],
            'rootfsLayerCount':len(audit['layers']),'nativeConfigProjectionHash':digest({k:native['Config'].get(k) for k in FIELDS}),
            'nativeRootfsHash':digest(native['RootFS']),'imageByteCustodyProven':True,
            'completeContainerOciProven':False,'transportClosureProven':False,'targetApplyAuthorized':False}

