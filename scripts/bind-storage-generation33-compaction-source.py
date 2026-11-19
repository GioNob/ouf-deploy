#!/usr/bin/env python3
"""Bind the reviewed upstream compaction paths to the candidate's full patch list."""
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
UPSTREAM='984eac6a790be89e2a11de175a7413e1e3e32dd3'
SOURCES={
    'weed/storage/store_vacuum.go':'2ffb157a058359f8279eb1d973d0b173059de1947620e65cf1c14649a132814c',
    'weed/command/volume.go':'5816a02b60965936952247c7cc6ae4d8239f4205d9eaf5aaf608d7a9efaeeb07',
    'weed/server/volume_grpc_vacuum.go':'a35efc7af662020e803e32a42f8f6ee6ad74ec20b34ebb286bde3ea4fb61b304',
    'weed/storage/volume_vacuum.go':'725690746dcb0bfaf05a8ded782fc2971ba483bb8652b763d839eb9f61c4f96a',
    'weed/topology/topology_vacuum.go':'9671a1fb2722e85e15ed6cd103397b8667560538553e6a40e941b832681a6976',
}

def sha(raw):return hashlib.sha256(raw).hexdigest()

def bind(out):
    out.mkdir()
    lock=json.loads((ROOT/'releases/seaweedfs-452-generation33-candidate-lock-20261104.json').read_bytes())
    raw=(ROOT/lock['buildManifest']['path']).read_bytes()
    assert sha(raw)==lock['buildManifest']['sha256']
    manifest=json.loads(raw)
    assert manifest['upstreamCommit']==lock['upstreamCommit']==UPSTREAM
    assert manifest['rootSourceGitTree']==lock['buildManifest']['rootSourceTree']
    patches=manifest['orderedSourcePatches']+manifest['orderedDependencyPatches']
    assert len(patches)==lock['orderedPatchCount']==33
    verified={}
    for patch in patches:
        data=(ROOT/patch['path']).read_bytes();assert sha(data)==patch['sha256']
        # Reject any patch touching a reviewed path, including rename headers.
        for line in data.decode().splitlines():
            if line.startswith(('diff --git ','--- ','+++ ','rename from ','rename to ','copy from ','copy to ')):
                assert not any(path in line for path in SOURCES), 'REVIEWED_SOURCE_MODIFIED_BY_PATCH: '+patch['path']
        verified[patch['path']]=sha(data)
    for path,digest in SOURCES.items():
        url='https://raw.githubusercontent.com/seaweedfs/seaweedfs/'+UPSTREAM+'/'+path
        with urllib.request.urlopen(url,timeout=30) as response: data=response.read(1048577)
        assert len(data)<=1048576 and sha(data)==digest, 'EXACT_REVIEWED_UPSTREAM_SOURCE_REQUIRED'
        (out/path.replace('/','__')).write_bytes(data)
    receipt={'upstreamCommit':UPSTREAM,'patchedRootSourceTree':manifest['rootSourceGitTree'],
             'reviewedUnmodifiedSourceSha256':SOURCES,'allOrderedPatchesVerified':verified,
             'binarySha256':lock['buildProfile']['binarySha256'],'ociManifestDigest':lock['image']['manifestDigest'],
             'instrumentedBuild':False,'scope':'reviewed paths unchanged by all generation33 patches; candidate binding, not a rebuild'}
    (out/'source-binding.json').write_text(json.dumps(receipt,indent=2)+'\n')

if __name__=='__main__':bind(Path(sys.argv[1]))
