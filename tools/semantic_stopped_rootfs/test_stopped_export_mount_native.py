"""Disposable Engine 29 fixture: test direct rootfs observation during export.

This is a feasibility test, never a target operator command or acceptance.
No candidate task is created or started. Preserve strict v1 seals, including
all xattrs and link counts; explicitly report any backend incompatibility.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

sys.path.insert(0, str(Path(__file__).parent))
from prepare_provider_image_rootfs import load_sealer, Budget


def main():
    assert os.geteuid() == 0
    here = Path(__file__).parent
    source = here / 'cohort-draft'
    sealer = load_sealer(source, hashlib.sha256((source/'sources.json').read_bytes()).hexdigest())
    limits = {'maxBytes': 67108864, 'maxEntries': 1024, 'maxDepth': 16}
    with tempfile.TemporaryDirectory(prefix='ouf-stopped-export-', dir='/root') as temp:
        root = Path(temp)
        cfg = root/'daemon.json'
        cfg.write_text(json.dumps({'features': {'containerd-snapshotter': True}}))
        socket = 'unix://' + str(root/'docker.sock')
        daemon = subprocess.Popen([shutil.which('dockerd'), '--config-file', str(cfg),
            '--data-root', str(root/'data'), '--exec-root', str(root/'exec'),
            '--pidfile', str(root/'pid'), '-H', socket, '--bridge', 'none',
            '--iptables=false', '--ip6tables=false', '--storage-driver', 'overlayfs'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        export = None; expected_view = None
        try:
            def docker(*args):
                return subprocess.run([shutil.which('docker'), '-H', socket, *map(str,args)],
                    capture_output=True, timeout=60, check=True).stdout
            deadline = time.monotonic()+60
            while True:
                try:
                    info = json.loads(docker('info','--format','{{json .}}')); break
                except subprocess.CalledProcessError:
                    assert daemon.poll() is None and time.monotonic()<deadline
                    time.sleep(.2)
            assert info['ServerVersion']=='29.8.1' and info['Driver']=='overlayfs'
            expected = root/'expected'; expected.mkdir(mode=0o755); expected.chmod(0o755)
            (expected/'data').mkdir(mode=0o755)
            # Large deterministic content keeps export blocked by its stdout pipe.
            (expected/'data/value').write_bytes(b'OUF-INDEPENDENT-CI\n'*524288)
            (expected/'data/value').chmod(0o640); os.chown(expected/'data/value',10006,10006)
            os.setxattr(expected/'data/value','user.ouf',b'approved')
            os.link(expected/'data/value',expected/'data/twin')
            (expected/'data/current').symlink_to('value')
            image_tar=root/'fixture.tar'
            with tarfile.open(image_tar,'w',format=tarfile.PAX_FORMAT) as archive:
                def xattr_header(item):
                    if item.name=='./data/value':
                        item.pax_headers['SCHILY.xattr.user.ouf']='approved'
                    return item
                archive.add(expected,arcname='.',recursive=True,filter=xattr_header)
            image=docker('import',image_tar).decode().strip()
            secret=root/'private-bind'; secret.write_bytes(b'NOT-IMAGE-CONTENT')
            cid=docker('create','--network','none','--mount',
                'type=bind,source='+str(secret)+',target=/private-bind,readonly',
                image,'/not-executed').decode().strip()
            before=json.loads(docker('inspect',cid))[0]
            assert before['State']['Status']=='created' and before['State']['Pid']==0
            # Independently authored engine init additions, not observed target data.
            for name in ('dev','dev/pts','dev/shm','proc','sys','etc'):
                (expected/name).mkdir(mode=0o755); (expected/name).chmod(0o755)
            for name in ('.dockerenv','etc/resolv.conf','etc/hosts','etc/hostname','dev/console'):
                (expected/name).write_bytes(b''); (expected/name).chmod(0o755)
            (expected/'etc/mtab').symlink_to('/proc/mounts')
            offline_seal=sealer(expected,limits,Budget())
            # OverlayFS synthesizes the merged root's directory link count.
            # Derive an independently mounted expected view; retain every
            # metadata field and the original offline seal, without masking
            # the observed container's differences or copying its metadata.
            expected_view=root/'expected-overlay'; expected_view.mkdir(mode=0o700)
            (root/'expected-upper').mkdir(mode=0o700)
            (root/'expected-work').mkdir(mode=0o700)
            options='lowerdir='+str(expected)+',upperdir='+str(root/'expected-upper')+',workdir='+str(root/'expected-work')
            subprocess.run(['mount','-t','overlay','overlay','-o',options,str(expected_view)],check=True)
            expected_seal=sealer(expected_view,limits,Budget())
            mounted=root/'data/rootfs/overlayfs'/cid
            export=subprocess.Popen([shutil.which('docker'),'-H',socket,'export',cid],
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            deadline=time.monotonic()+20
            while not os.path.ismount(mounted):
                assert export.poll() is None and time.monotonic()<deadline, 'EXPORT_MOUNT_NOT_OBSERVABLE'
                time.sleep(.05)
            actual_seal=sealer(mounted,limits,Budget())
            assert export.poll() is None, 'EXPORT_NOT_HELD_DURING_SEAL'
            assert not (mounted/'private-bind').exists(), 'BIND_SOURCE_EXPOSED'
            # Retain bounded CI-only metadata differences instead of normalizing.
            differences=[]
            for path in [expected_view,*sorted(expected_view.rglob('*'))]:
                relative=path.relative_to(expected_view)
                actual=mounted/relative; left=path.lstat(); right=actual.lstat()
                for field in ('st_mode','st_uid','st_gid','st_nlink','st_size'):
                    if field=='st_size' and path.is_dir(): continue
                    if getattr(left,field)!=getattr(right,field):
                        differences.append({'path':str(relative),'field':field,'expected':getattr(left,field),'actual':getattr(right,field)})
                if not path.is_symlink():
                    l={n:os.getxattr(path,n).hex() for n in os.listxattr(path)}
                    r={n:os.getxattr(actual,n).hex() for n in os.listxattr(actual)}
                    if l!=r: differences.append({'path':str(relative),'field':'xattrs','expected':l,'actual':r})
            selector=selectors.DefaultSelector(); selector.register(export.stdout,selectors.EVENT_READ)
            drained=0; deadline=time.monotonic()+30
            while True:
                assert time.monotonic()<deadline, 'EXPORT_DRAIN_TIMEOUT'
                events=selector.select(.2)
                if not events: continue
                chunk=os.read(export.stdout.fileno(),65536)
                if not chunk: break
                drained+=len(chunk); assert drained<=67108864
            selector.close(); assert export.wait(timeout=10)==0
            after=json.loads(docker('inspect',cid))[0]
            assert before['State']==after['State'], 'STOPPED_CANDIDATE_STATE_CHANGED'
            deadline=time.monotonic()+10
            while os.path.ismount(mounted):
                assert time.monotonic()<deadline, 'EXPORT_MOUNT_RETAINED'
                time.sleep(.05)
            result={'schema':'ouf.stopped-export-mount-ci.v1','engineVersion':info['ServerVersion'],
                'directMountedRootfsObserved':True,'neverStarted':True,'privateBindContentRead':False,
                'mountReleased':True,'strictSealMatches':actual_seal==expected_seal,
                'originalOfflineSeal':offline_seal,'independentExpectedOverlayView':True,
                'expectedSeal':expected_seal,'actualSeal':actual_seal,'metadataDifferences':differences,
                'targetOperations':0,'targetAcceptance':False}
            print('OUF_STOPPED_EXPORT_MOUNT_CI='+json.dumps(result,sort_keys=True))
            assert actual_seal==expected_seal, 'STRICT_SEAL_BACKEND_COMPATIBILITY_UNPROVEN'
        finally:
            if export is not None and export.poll() is None:
                export.kill(); export.wait(timeout=10)
            if expected_view is not None and os.path.ismount(expected_view):
                subprocess.run(['umount',str(expected_view)],check=True,timeout=10)
            daemon.terminate()
            try:daemon.wait(timeout=20)
            except subprocess.TimeoutExpired:daemon.kill();daemon.wait(timeout=5)

if __name__=='__main__':main()
