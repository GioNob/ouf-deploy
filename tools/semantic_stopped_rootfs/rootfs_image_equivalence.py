"""Compare image semantics independently of merged-directory inode counters.

All original v1 records/seals remain intact. Directory st_nlink is synthesized
by OverlayFS and is not OCI layer metadata. File link counts remain exact.
The root mode is derived from authenticated image layer headers, falling back
to Engine/containerd's 0755 when the image supplies no root directory entry.
No observed target value is used to choose the expected mode.
"""
import hashlib
import tarfile
from pathlib import Path
from prepare_provider_image_rootfs import Budget,canonical,decode,private,require,sha
from rootfs_difference_report import classify


def layer_root_mode(layers):
    mode=0o755;explicit=0;count=0;budget=Budget()
    for path in layers:
        with tarfile.open(path,mode='r|*') as stream:
            for item in stream:
                count+=1;budget.check(item.size)
                require(count<=100000 and item.size<=8589934592,'ROOT_MODE_LAYER_UNBOUNDED')
                if item.name.rstrip('/') in ('','.'): 
                    require(item.isdir(),'IMAGE_ROOT_DIRECTORY_REQUIRED')
                    mode=item.mode&0o7777;explicit+=1
                stream.members.clear()
    return {'mode':mode,'explicitRootHeaderCount':explicit,
        'origin':'IMAGE_LAYER_ROOT_HEADER' if explicit else 'ENGINE_SNAPSHOT_DEFAULT_0755'}


def expected_root_mode(layout,manifest_digest):
    require(manifest_digest.startswith('sha256:') and len(manifest_digest)==71,'MANIFEST_DIGEST_REQUIRED')
    raw=private(Path(layout)/'blobs/sha256'/manifest_digest[7:])
    require('sha256:'+sha(raw)==manifest_digest,'ROOT_MODE_MANIFEST_DRIFT')
    manifest=decode(raw);layers=[]
    require(1<=len(manifest['layers'])<=128,'ROOT_MODE_LAYERS_UNBOUNDED')
    for descriptor in manifest['layers']:
        digest=descriptor['digest']
        require(digest.startswith('sha256:') and len(digest)==71
            and all(c in '0123456789abcdef' for c in digest[7:]),'LAYER_DIGEST_REQUIRED')
        layers.append(Path(layout)/'blobs/sha256'/digest[7:])
    return layer_root_mode(layers)


def compare_image_entries(expected,actual,root_policy):
    left={};right={};directory_link_differences=0
    for collection,output,is_expected in ((expected,left,True),(actual,right,False)):
        for path,item in collection.items():
            value=dict(item)
            if value['kind']=='directory':value.pop('links')
            if path=='' and is_expected:
                require(value['kind']=='directory','EXPECTED_ROOT_DIRECTORY_REQUIRED')
                value['mode']=root_policy['mode']
            output[path]=value
    for path,item in expected.items():
        peer=actual.get(path)
        if peer and item['kind']==peer['kind']=='directory' and item['links']!=peer['links']:
            directory_link_differences+=1
    differences=classify(left,right)
    def seal(records):
        h=hashlib.sha256(b'OUF-IMAGE-EQUIVALENCE\x00V1\x00')
        for path in sorted(records):
            raw=canonical(records[path]);h.update(len(raw).to_bytes(4,'big'));h.update(raw)
        return h.hexdigest()
    return {'schema':'ouf.image-rootfs-equivalence.v1','equivalent':left==right,
        'expectedImageSeal':seal(left),'actualImageSeal':seal(right),
        'directoryLinkCounterDifferences':directory_link_differences,
        'directoryLinkCountersAreImageMetadata':False,'regularFileLinkCountsCompared':True,
        'expectedRootMode':root_policy,'actualRootMode':actual.get('',{}).get('mode'),
        'differences':differences,'originalV1SealsRetained':True}
