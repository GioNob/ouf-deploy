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
