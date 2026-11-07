"""Explicit partial OCI indexes; inert archive members, no runtime acceptance."""
from retained_image_bytes import fixture,package,encoded,address


def partial_index(*,role='graph-fixture'):
    _,runtime,entries=fixture(role=role)
    runtime_raw=entries[2][1]
    existing={'mediaType':'application/vnd.oci.image.manifest.v1+json','digest':runtime,
        'size':len(runtime_raw),'platform':{'os':'linux','architecture':'amd64'}}
    missing={'mediaType':'application/vnd.oci.image.manifest.v1+json','digest':'sha256:'+'a'*64,
        'size':500,'platform':{'os':'linux','architecture':'arm64','variant':'v8'}}
    auxiliary={'mediaType':'application/vnd.oci.image.manifest.v1+json','digest':'sha256:'+'b'*64,
        'size':600,'platform':{'os':'unknown','architecture':'unknown'},
        'annotations':{'vnd.docker.reference.type':'attestation-manifest','vnd.docker.reference.digest':runtime}}
    index=encoded({'schemaVersion':2,'mediaType':'application/vnd.oci.image.index.v1+json',
        'manifests':[existing,missing,auxiliary]})
    root={'mediaType':'application/vnd.oci.image.index.v1+json','digest':address(index),'size':len(index)}
    classic=encoded([{'Config':entries[3][0],'Layers':[entries[4][0]],'RepoTags':['PRIVATE_TAG_NEVER_PRINT']}])
    entries=[entries[0],('index.json',encoded({'schemaVersion':2,'manifests':[root]})),*entries[2:],
        ('blobs/sha256/'+address(index)[7:],index),('manifest.json',classic)]
    return package(entries),address(index),entries
