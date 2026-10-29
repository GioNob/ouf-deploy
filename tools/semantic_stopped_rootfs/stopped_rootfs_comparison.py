"""Bounded direct filesystem observation; never create or start a task."""
import os
from pathlib import Path
import re
import selectors
import subprocess
import time
from contextlib import contextmanager

from prepare_provider_image_rootfs import ancestors, attributes, program, require


def validated(binding):
    program(*binding)
    return str(binding[0])


def wait_unmounted(path, seconds=10):
    deadline=time.monotonic()+seconds
    while os.path.ismount(path):
        require(time.monotonic()<deadline,'EXPORT_MOUNT_RETAINED')
        time.sleep(.05)


@contextmanager
def expected_overlay(lower, directory, mount_binding, umount_binding):
    """Render independently sealed content through the actual filesystem backend.

    No field is normalized or read from the observed candidate. Copy root
    ownership, mode and every root xattr from the independent offline tree.
    Retain the offline seal separately from the overlay view's complete seal.
    """
    lower=Path(lower);directory=Path(directory)
    ancestors(lower);ancestors(directory)
    require(lower.is_dir() and not lower.is_symlink() and directory.is_dir()
            and not directory.is_symlink() and not list(directory.iterdir()),'EXPECTED_VIEW_DIRECTORY_REQUIRED')
    require(not any(c in str(lower)+str(directory) for c in ',:\n'),'OVERLAY_PATH_UNSUPPORTED')
    mount=validated(mount_binding);umount=validated(umount_binding)
    view=directory/'view';upper=directory/'upper';work=directory/'work'
    for path in (view,upper,work):path.mkdir(mode=0o700)
    before=lower.lstat();upper.chmod(before.st_mode&0o7777);os.chown(upper,before.st_uid,before.st_gid)
    for name in os.listxattr(lower):os.setxattr(upper,name,os.getxattr(lower,name))
    require(attributes(before)==attributes(lower.lstat()),'EXPECTED_ROOT_CHANGED')
    options='lowerdir='+str(lower)+',upperdir='+str(upper)+',workdir='+str(work)
    mounted=False
    try:
        subprocess.run([mount,'-t','overlay','overlay','-o',options,str(view)],
            check=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        mounted=True;require(os.path.ismount(view),'EXPECTED_OVERLAY_MOUNT_UNPROVEN')
        program(*mount_binding);yield view
    finally:
        if mounted:
            program(*umount_binding)
            subprocess.run([umount,str(view)],check=True,stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            wait_unmounted(view)


@contextmanager
def stopped_export_view(docker_binding, socket, config, cid, rootfs, max_export_bytes=17179869184):
    """Use daemon export's mount lifecycle; preserve complete mounted metadata.

    Holding stdout keeps io.Copy alive. Tar data is discarded after observation,
    never unpacked or accepted as a replacement for direct filesystem metadata.
    """
    require(re.fullmatch('[0-9a-f]{64}',cid) and socket.startswith('unix:///'),'EXPORT_BINDING_REQUIRED')
    require(type(max_export_bytes) is int and 0<max_export_bytes<=17179869184,'EXPORT_BOUND_REQUIRED')
    rootfs=Path(rootfs);config=Path(config);ancestors(rootfs);ancestors(config)
    require(not os.path.ismount(rootfs),'ROOTFS_ALREADY_MOUNTED')
    executable=validated(docker_binding)
    process=subprocess.Popen([executable,'--host',socket,'--config',str(config),'export',cid],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    completed=False;selector=None
    try:
        deadline=time.monotonic()+20
        while not os.path.ismount(rootfs):
            require(process.poll() is None and time.monotonic()<deadline,'EXPORT_MOUNT_NOT_OBSERVABLE')
            time.sleep(.05)
        require(not rootfs.is_symlink(),'ROOTFS_SYMLINK_DENIED');program(*docker_binding)
        yield rootfs
        require(process.poll() is None and os.path.ismount(rootfs),'EXPORT_NOT_HELD_DURING_SEAL')
        selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
        total=0;deadline=time.monotonic()+60
        while True:
            require(time.monotonic()<deadline,'EXPORT_DRAIN_TIMEOUT')
            if not selector.select(.2):continue
            raw=os.read(process.stdout.fileno(),65536)
            if not raw:break
            total+=len(raw);require(total<=max_export_bytes,'EXPORT_BYTES_UNBOUNDED')
        require(process.wait(timeout=10)==0,'EXPORT_COMMAND_FAILED')
        program(*docker_binding);wait_unmounted(rootfs);completed=True
    finally:
        if selector is not None:selector.close()
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        if not completed:wait_unmounted(rootfs)
