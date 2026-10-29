"""Real pinned umoci unpack vs independently authored expected filesystem."""
import gzip
import hashlib
import io
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
sys.path.insert(0,str(Path(__file__).parent))
from prepare_provider_image_rootfs import prepare,apply_docker_init,canonical,load_sealer,Budget,OCI_MANIFEST,OCI_CONFIG

def digest(raw):return 'sha256:'+hashlib.sha256(raw).hexdigest()
def layer(rows):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w',format=tarfile.PAX_FORMAT) as archive:
        for name,kind,data in rows:
            item=tarfile.TarInfo(name);item.uid=item.gid=0;item.mode=0o755 if kind=='dir' else 0o640
            if kind=='dir':item.type=tarfile.DIRTYPE
            elif kind=='link':item.type=tarfile.LNKTYPE;item.linkname=data;item.uid=item.gid=10006
            elif kind=='symlink':item.type=tarfile.SYMTYPE;item.linkname=data;item.mode=0o777
            else:
                item.uid=item.gid=10006;item.size=len(data)
                if name=='bin/data':item.pax_headers={'SCHILY.xattr.user.ouf':'approved'}
            archive.addfile(item,io.BytesIO(data) if kind=='file' else None)
    return stream.getvalue()
def main():
    assert os.geteuid()==0
    here=Path(__file__).parent;source=here/'cohort-draft';umoci=here/'umoci'
    source_hash=hashlib.sha256((source/'sources.json').read_bytes()).hexdigest();umoci_hash=hashlib.sha256(umoci.read_bytes()).hexdigest()
    first=layer([('.', 'dir',None),('bin','dir',None),('bin/data','file',b'good'),('bin/twin','link','bin/data'),
        ('bin/current','symlink','data'),('bin/deleted','file',b'bad'),('obsolete','dir',None),('obsolete/old','file',b'bad')])
    second=layer([('obsolete/new','file',b'new'),('obsolete/.wh..wh..opq','file',b''),('bin/.wh.deleted','file',b'')])
    layers=[gzip.compress(raw,mtime=0) for raw in (first,second)]
    config=canonical({'os':'linux','architecture':'amd64','rootfs':{'type':'layers','diff_ids':[digest(first),digest(second)]},
        'config':{'User':'10006:10006','Cmd':['/bin/data']}})
    manifest=canonical({'schemaVersion':2,'mediaType':OCI_MANIFEST,'config':{'mediaType':OCI_CONFIG,'digest':digest(config),'size':len(config)},
        'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar+gzip','digest':digest(raw),'size':len(raw)} for raw in layers]})
    with tempfile.TemporaryDirectory(prefix='ouf-offline-rootfs-',dir='/root') as temporary:
        root=Path(temporary);archive=root/'image.tar.gz';outer=io.BytesIO()
        with tarfile.open(fileobj=outer,mode='w') as target:
            values={'oci-layout':canonical({'imageLayoutVersion':'1.0.0'}),**{'blobs/sha256/'+digest(raw)[7:]:raw for raw in (*layers,config,manifest)}}
            for name,raw in values.items():item=tarfile.TarInfo(name);item.size=len(raw);target.addfile(item,io.BytesIO(raw))
        archive.write_bytes(gzip.compress(outer.getvalue(),mtime=0));archive.chmod(0o600)
        output=root/'output';output.mkdir(mode=0o700)
        result=prepare(archive,hashlib.sha256(archive.read_bytes()).hexdigest(),digest(manifest),digest(config),umoci,umoci_hash,source,source_hash,output)
        expected=root/'expected';expected.mkdir(mode=0o755);expected.chmod(0o755)
        for name in ('bin','obsolete'):
            (expected/name).mkdir(mode=0o755);(expected/name).chmod(0o755)
        (expected/'bin/data').write_bytes(b'good');(expected/'bin/data').chmod(0o640);os.chown(expected/'bin/data',10006,10006)
        os.setxattr(expected/'bin/data','user.ouf',b'approved');os.link(expected/'bin/data',expected/'bin/twin')
        (expected/'bin/current').symlink_to('data')
        (expected/'obsolete/new').write_bytes(b'new');(expected/'obsolete/new').chmod(0o640);os.chown(expected/'obsolete/new',10006,10006)
        sealer=load_sealer(source,source_hash);expected_seal=sealer(expected,result['rootfsLimits'],Budget())
        assert result['rootfsSeal']==expected_seal,(result['rootfsSeal'],expected_seal)
        assert not (output/'bundle/rootfs/bin/deleted').exists() and not (output/'bundle/rootfs/obsolete/old').exists()
        assert os.stat(output/'bundle/rootfs/bin/data').st_nlink==2
        assert result['containerLifecycleOperations']==0 and result['startAuthorized'] is False
        init_tool=here/'docker-initlayer';init_hash=hashlib.sha256(init_tool.read_bytes()).hexdigest()
        docker=apply_docker_init(output,init_tool,init_hash,'464cd50c3d9e92877d56940ea160de6fca7bea23',source,source_hash)
        for name in ('dev','dev/pts','dev/shm','proc','sys','etc'):
            (expected/name).mkdir(mode=0o755);(expected/name).chmod(0o755)
        for name in ('.dockerenv','etc/resolv.conf','etc/hosts','etc/hostname','dev/console'):
            (expected/name).write_bytes(b'');(expected/name).chmod(0o755)
        (expected/'etc/mtab').symlink_to('/proc/mounts')
        assert docker['rootfsSeal']==sealer(expected,docker['rootfsLimits'],Budget())
        assert docker['imageRootfsSeal']==result['rootfsSeal'] and docker['targetRootfsCompared'] is False
        print('OFFLINE_IMAGE_ROOTFS_NATIVE=PASS REAL_UMOCI=true INDEPENDENT_EXPECTED_FILESYSTEM=true WHITEOUT_OPAQUE_HARDLINK_SYMLINK_UID_MODE_XATTR=true CONTAINER_OPERATIONS=0 TARGET_ACCEPTANCE=false')
        print('OFFLINE_DOCKER_ROOTFS_NATIVE=PASS OBSERVED_ENGINE_INITLAYER_SOURCE=true INDEPENDENT_EXPECTED_ENGINE_ADDITIONS=true ORIGINAL_IMAGE_SEAL_RETAINED=true CONTAINER_OPERATIONS=0 TARGET_ACCEPTANCE=false')
if __name__=='__main__':main()
