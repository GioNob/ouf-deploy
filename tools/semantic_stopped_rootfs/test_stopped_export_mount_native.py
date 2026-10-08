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
from stopped_rootfs_comparison import expected_overlay, stopped_export_view


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
            cid=docker('create','--name','ouf-ci-stopped-candidate','--network','none','--mount',
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
            def binding(name):
                path=Path(shutil.which(name)).resolve()
                return (path,hashlib.sha256(path.read_bytes()).hexdigest())
            # Execute the fixed entrypoint's entire validation/reporting flow
            # against CI-owned locations; its shipped target constants remain
            # fixed and no runtime arguments can override them.
            import compare_provider_v2_stopped_rootfs as entry
            offline=root/'offline'; offline.mkdir(mode=0o700)
            shutil.copytree(source,offline/'source')
            role_dir=offline/'adapter'; role_dir.mkdir(mode=0o700)
            (role_dir/'bundle').mkdir(mode=0o700)
            shutil.copytree(expected,role_dir/'bundle/rootfs',copy_function=shutil.copy2,symlinks=True)
            # copytree does not preserve hardlinks; reconstruct the independent
            # fixture alias explicitly rather than changing expected metadata.
            (role_dir/'bundle/rootfs/data/twin').unlink()
            os.link(role_dir/'bundle/rootfs/data/value',role_dir/'bundle/rootfs/data/twin')
            for name in ('data/value','data/twin'):
                os.chown(role_dir/'bundle/rootfs'/name,10006,10006)
            from prepare_provider_image_rootfs import canonical,write_once
            spec={'cid':cid,'name':'ouf-ci-stopped-candidate','archive':'a'*64,
                'manifest':image,'config':'sha256:'+'b'*64,'seal':offline_seal['sha256']}
            receipt={'schema':'ouf.semantic-offline-docker-rootfs.v1',
                'sourceManifestSha256':entry.SOURCE_MANIFEST,
                'engineCommit':'464cd50c3d9e92877d56940ea160de6fca7bea23',
                'archiveSha256':spec['archive'],'manifestDigest':spec['manifest'],
                'configDigest':spec['config'],'rootfsSeal':offline_seal,'rootfsLimits':limits,
                'offlineDockerInitLayerApplied':True,'targetRootfsCompared':False}
            write_once(role_dir/'expected-docker-rootfs.json',canonical(receipt))
            entry.OFFLINE=offline;entry.DATA_ROOT=root/'data';entry.SNAPSHOT_PARENT=root
            entry.SOCKET=socket;entry.DOCKER=binding('docker');entry.MOUNT=binding('mount');entry.UMOUNT=binding('umount')
            entry.ROLES={'adapter':spec}
            entry.main()
            config=root/'docker-config'; config.mkdir(mode=0o700)
            overlay_dir=root/'expected-overlay'; overlay_dir.mkdir(mode=0o700)
            mounted=root/'data/rootfs/overlayfs'/cid
            with expected_overlay(expected,overlay_dir,binding('mount'),binding('umount')) as expected_view:
                expected_seal=sealer(expected_view,limits,Budget())
                with stopped_export_view(binding('docker'),socket,config,cid,mounted,67108864) as actual:
                    actual_seal=sealer(actual,limits,Budget())
                    assert not (actual/'private-bind').exists(), 'BIND_SOURCE_EXPOSED'
                    assert actual_seal==expected_seal, 'STRICT_SEAL_BACKEND_COMPATIBILITY_UNPROVEN'
                # A second observation must reject bytes that diverge from
                # the same independent expectation; never adopt target bytes.
                changed=root/'changed'; changed.write_bytes(b'UNAPPROVED')
                docker('cp',changed,cid+':/data/value')
                with stopped_export_view(binding('docker'),socket,config,cid,mounted,67108864) as actual:
                    changed_seal=sealer(actual,limits,Budget())
                    assert changed_seal!=expected_seal, 'UNAPPROVED_CONTENT_NOT_DETECTED'
                entry.main(diagnose=True)
                reports=sorted(root.glob('semantic-provider-v2-rootfs-compare-*/comparison.json'),key=lambda p:p.stat().st_mtime_ns)
                diagnostic=json.loads(reports[-1].read_bytes())
                assert diagnostic['status']=='READ_ONLY_DIFFERENCE_DIAGNOSIS'
                assert diagnostic['strictSealsMatch'] is False
                diff=diagnostic['roles'][0]['differences']
                assert diff['fieldCounts']['sha256']>=1 and diff['fileContentsPrinted'] is False
            differences=[]
            after=json.loads(docker('inspect',cid))[0]
            assert before['State']==after['State'], 'STOPPED_CANDIDATE_STATE_CHANGED'
            deadline=time.monotonic()+10
            while os.path.ismount(mounted):
                assert time.monotonic()<deadline, 'EXPORT_MOUNT_RETAINED'
                time.sleep(.05)
            result={'schema':'ouf.stopped-export-mount-ci.v1','engineVersion':info['ServerVersion'],
                'directMountedRootfsObserved':True,'neverStarted':True,'privateBindContentRead':False,
                'mountReleased':True,'strictSealMatches':actual_seal==expected_seal,'unapprovedContentDetected':True,'productionComparisonFunctionsUsed':True,'fixedEntrypointExercised':True,
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
