"""Small inert Docker/OCI archives; no container, executable or publisher trust."""
import gzip,hashlib,io,json,tarfile


def encoded(value):return json.dumps(value,separators=(',',':')).encode()
def address(raw):return 'sha256:'+hashlib.sha256(raw).hexdigest()
def package(entries):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w') as tar:
        for name,raw in entries:
            if isinstance(raw,tarfile.TarInfo):tar.addfile(raw);continue
            row=tarfile.TarInfo(name);row.size=len(raw);tar.addfile(row,io.BytesIO(raw))
    return output.getvalue()
def fixture(*,native=True,compressed=True,role='fixture',bad_diff=False):
    content=package([('inert-data',b'PRIVATE_IMAGE_VALUE_NEVER_PRINT_OR_EXECUTE')])
    layer=gzip.compress(content,mtime=0) if compressed else content
    config={'architecture':'amd64','os':'linux','config':{'User':'10001:10001',
        'Labels':{'ouf.fixture.role':role},'Env':['PRIVATE_IMAGE_ENV_VALUE=never-print']},
        'rootfs':{'type':'layers','diff_ids':[('sha256:'+'f'*64) if bad_diff else address(content)]}}
    config_raw=encoded(config);config_hash=address(config_raw);layer_hash=address(layer)
    if native:
        descriptor=lambda media,raw:{'mediaType':media,'digest':address(raw),'size':len(raw)}
        manifest={'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json',
            'config':descriptor('application/vnd.oci.image.config.v1+json',config_raw),
            'layers':[descriptor('application/vnd.oci.image.layer.v1.tar'+('+gzip' if compressed else ''),layer)]}
        raw=encoded(manifest);image=address(raw)
        index={'schemaVersion':2,'manifests':[descriptor(manifest['mediaType'],raw)]}
        entries=[('oci-layout',encoded({'imageLayoutVersion':'1.0.0'})),('index.json',encoded(index)),
            ('blobs/sha256/'+image[7:],raw),('blobs/sha256/'+config_hash[7:],config_raw),
            ('blobs/sha256/'+layer_hash[7:],layer)]
    else:
        image=config_hash
        entries=[('manifest.json',encoded([{'Config':config_hash[7:]+'.json','Layers':['layer.tar']}]))
            ,(config_hash[7:]+'.json',config_raw),('layer.tar',layer)]
    raw=package(entries)
    return raw,image,entries


def attested_fixture(*,modern=True,inline_empty=False,bad_blob=False,wrong_subject=False,wrong_platform=False):
    _,image,entries=fixture()
    manifest_body=entries[2][1]
    descriptor=lambda media,raw:{'mediaType':media,'digest':address(raw),'size':len(raw)}
    runtime=descriptor('application/vnd.oci.image.manifest.v1+json',manifest_body)
    runtime['platform']={'architecture':'amd64','os':'linux'}
    content=encoded({'_type':'https://in-toto.io/Statement/v1','predicateType':'https://slsa.dev/provenance/v1',
        'subject':[{'name':'_','digest':{'sha256':image[7:]}}],'predicate':{'fixture':'PRIVATE_ATTESTATION_BODY'}})
    raw_config=b'{}' if modern else encoded({'architecture':'unknown','os':'unknown','rootfs':{'type':'layers','diff_ids':[]}})
    cfg=descriptor('application/vnd.oci.empty.v1+json' if modern else 'application/vnd.oci.image.config.v1+json',raw_config)
    if modern:cfg['data']='e30='
    artifact={'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json',
        'config':cfg,'layers':[descriptor('application/vnd.in-toto+json',content)]}
    target=('sha256:'+'f'*64) if wrong_subject else image
    if modern:artifact.update(artifactType='application/vnd.docker.attestation.manifest.v1+json',
        subject={**runtime,'digest':target})
    artifact_raw=encoded(artifact);attestation=descriptor(artifact['mediaType'],artifact_raw)
    attestation['platform']={'architecture':'amd64' if wrong_platform else 'unknown','os':'unknown'}
    attestation['annotations']={'vnd.docker.reference.type':'attestation-manifest','vnd.docker.reference.digest':target}
    index_raw=encoded({'schemaVersion':2,'manifests':[runtime,attestation]})
    root=descriptor('application/vnd.oci.image.index.v1+json',index_raw)
    entries=[entries[0],('index.json',encoded({'schemaVersion':2,'manifests':[root]})),*entries[2:],
        ('blobs/sha256/'+root['digest'][7:],index_raw),('blobs/sha256/'+address(artifact_raw)[7:],artifact_raw),
        ('blobs/sha256/'+address(content)[7:],content+(b' ' if bad_blob else b''))]
    if not inline_empty or not modern:entries.append(('blobs/sha256/'+address(raw_config)[7:],raw_config))
    return package(entries),root['digest'],entries
