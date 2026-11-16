#!/usr/bin/env python3
"""D-042: correct upper-only mount ancestors and reseal stopped successors.

Plan reads metadata through the same bounded views as v2 and projects only the
0711 ancestor modes. Apply changes those physical directories through pinned
no-follow directory descriptors, then proves the complete D-042 difference.
No lifecycle operations, signatures or private mount contents.
"""
import argparse
import copy
import types
from contextlib import ExitStack
from contextlib import contextmanager
from datetime import datetime
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import shutil
import subprocess
import tempfile
import sys

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('b1_rootfs_v1', HERE / 'prepare-semantic-provider-b1-rootfs.py')
V1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(V1)
from prepare_provider_image_rootfs import (Budget, Denied, ancestors, canonical,
    decode, load_sealer, private, program, require, sha, write_once)
from rootfs_difference_report import entries

ROLES = V1.ROLES
OUTPUT_PARENT = Path('/var/lib/ouf-storage-migration')
SCHEMA = 'ouf.semantic-provider-b1-rootfs-evidence.v1'
PREPARED = 'SEMANTIC_PROVIDER_B1_ROOTFS_EVIDENCE_PREPARED'
EMPTY_SHA = sha(b'')
RULE = 'D-042'


def arguments(argv=None):
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--apply', action='store_true')
    p.add_argument('--plan-sha256', type=V1.matching('[0-9a-f]{64}'))
    p.add_argument('--date', type=V1.matching('[0-9]{8}'), required=True)
    for name in ('previous-result', 'a-successors', 'source', 'docker', 'mount', 'umount'):
        p.add_argument('--' + name, type=V1.absolute, required=True)
        suffix = 'manifest-sha256' if name == 'source' else 'sha256'
        p.add_argument('--' + name + '-' + suffix, type=V1.matching('[0-9a-f]{64}'), required=True)
    for role in ROLES:
        for name in ('frame-policy', 'oci-config'):
            p.add_argument('--' + role + '-' + name, type=V1.absolute, required=True)
            p.add_argument('--' + role + '-' + name + '-sha256', type=V1.matching('[0-9a-f]{64}'), required=True)
        for name in ('image-view', 'container-view'):
            p.add_argument('--' + role + '-' + name, type=V1.absolute, required=True)
    args = p.parse_args(argv)
    if args.apply != bool(args.plan_sha256):
        p.error('--plan-sha256 is required only with --apply')
    try:
        datetime.strptime(args.date, '%Y%m%d')
    except ValueError:
        p.error('invalid calendar date')
    return args


def bound(path, digest, inputs):
    path = Path(path)
    raw = private(path)
    require(sha(raw) == digest, 'INPUT_HASH_DRIFT')
    require(inputs.get(str(path), digest) == digest, 'INPUT_BINDING_CONFLICT')
    inputs[str(path)] = digest
    return decode(raw)


def binding_document(binding, inputs):
    require(type(binding) is dict and set(binding) == {'path', 'sha256'}, 'EXACT_INPUT_BINDING_REQUIRED')
    V1.absolute(binding['path'])
    require(re.fullmatch('[0-9a-f]{64}', binding['sha256']), 'EXACT_INPUT_BINDING_REQUIRED')
    return bound(binding['path'], binding['sha256'], inputs)


def relative_destination(value):
    require(type(value) is str and value.startswith('/') and not value.startswith('//') and value != '/' and
            str(PurePosixPath(value)) == value and '..' not in PurePosixPath(value).parts
            and not any(ord(c) < 32 or ord(c) == 127 for c in value), 'OCI_MOUNT_DESTINATION_REQUIRED')
    return value[1:]


def mount_targets(mounts, image, source_kind):
    """Only signed destinations absent in the image and their ancestors.

    source_kind reads lstat metadata only, never source contents. Existing image
    symlinks cannot be traversed to reinterpret an absent destination.
    """
    require(type(mounts) is list and len(mounts) <= 256, 'BOUNDED_OCI_MOUNTS_REQUIRED')
    targets = {}; seen = set()
    for mount in mounts:
        dest = relative_destination(mount['destination'])
        require(dest not in seen, 'DUPLICATE_OCI_MOUNT_DESTINATION')
        parts = PurePosixPath(dest).parts
        ancestors_ = ['/'.join(parts[:i]) for i in range(1, len(parts))]
        nested = any(a in seen for a in ancestors_)
        seen.add(dest)
        if nested:
            # runc creates it inside an earlier mount (/dev tmpfs, /sys, ...), never in the rootfs.
            continue
        for parent in ancestors_:
            require(parent not in image or image[parent]['kind'] == 'directory', 'OCI_MOUNT_ANCESTOR_NOT_DIRECTORY')
        if dest in image:
            continue
        if mount['type'] in ('tmpfs', 'proc', 'sysfs', 'devpts', 'mqueue', 'cgroup', 'cgroup2'):
            kind = 'directory'
        else:
            require(mount['type'] == 'bind', 'ABSENT_OCI_MOUNT_TYPE_UNSUPPORTED')
            kind = source_kind(mount['source'])
            require(kind in ('file', 'directory'), 'OCI_BIND_SOURCE_TYPE_DENIED')
        targets[dest] = kind
    allowed = dict(targets)
    copied = {''}
    for dest in targets:
        for parent in PurePosixPath(dest).parents:
            name = '' if str(parent) == '.' else str(parent)
            if name in image:
                copied.add(name)
            else:
                require(name not in allowed or allowed[name] == 'directory', 'NESTED_FILE_MOUNT_DENIED')
                allowed[name] = 'directory'
    return targets, allowed, copied



OVERLAY_BOOKKEEPING_XATTRS = frozenset({'trusted.overlay.origin', 'trusted.overlay.impure', 'trusted.overlay.nlink',
                                        'trusted.overlay.uuid'})


def physical(entry, new=False):
    """The upper layer carries overlayfs bookkeeping xattrs hidden by the merged view."""
    # Only copy-up bookkeeping is tolerated. opaque/redirect/metacopy could hide
    # or redirect image content and are always denied.
    # A brand-new directory (absent from the image) may be marked opaque: there is
    # nothing below it to hide. On a copied-up image directory opaque is denied.
    xattrs = entry.get('xattrs') or {}
    tolerated = OVERLAY_BOOKKEEPING_XATTRS | ({'trusted.overlay.opaque'} if new and entry.get('kind') == 'directory' else set())
    if not set(xattrs) <= tolerated:
        print('POST_CREATE_UPPER_XATTR_NAMES ' + json.dumps(sorted(xattrs)), file=sys.stderr)  # names only
    require(set(xattrs) <= tolerated, 'POST_CREATE_XATTR_DENIED')
    return {**entry, 'xattrs': {}} if 'xattrs' in entry else entry

def compare_entries(image, actual, upper, mounts, source_kind):
    """Exact sealed records, plus raw upper: no invisible replacement/whiteout.

    OverlayFS merged directory nlink is 1; an unmerged directory has the
    physical count 2 + immediate subdirectories. No global nlink exclusion.
    mtime/ctime are not fields of the historical seal and are never normalized.
    """
    targets, allowed, copied = mount_targets(mounts, image, source_kind)
    require(set(image) <= set(actual), 'POST_CREATE_IMAGE_ENTRY_MISSING')
    require(set(actual) - set(image) == set(allowed), 'POST_CREATE_UNDECLARED_PATH')
    require(set(upper) == {''} | set(allowed) | (set(upper) & copied), 'POST_CREATE_UPPER_UNDECLARED_PATH')
    require(all(p in upper for p in allowed), 'POST_CREATE_MOUNTPOINT_NOT_IN_UPPER')
    require(all(actual[p]['kind'] == kind for p, kind in allowed.items()), 'POST_CREATE_ENTRY_TYPE_DENIED')
    differences = []
    for name in sorted(actual):
        value = actual[name]
        old = image.get(name)
        if old is None:
            kind = allowed[name]
            require(value['kind'] == kind, 'POST_CREATE_ENTRY_TYPE_DENIED')
            if value.get('xattrs') != {}:
                print('POST_CREATE_VIEW_XATTR_NAMES ' + json.dumps({'path': name, 'names': sorted(value.get('xattrs') or {})}),
                      file=sys.stderr)  # names only, never values
            require(value.get('xattrs') == {}, 'POST_CREATE_XATTR_DENIED')
            require(value['uid'] == value['gid'] == 0, 'POST_CREATE_OWNER_DENIED')
            require(value['mode'] == (0o711 if name not in targets else 0o600 if kind == 'file' else 0o700),
                    'POST_CREATE_MODE_DENIED')
            if name not in targets:
                require(upper[name].get('xattrs') == {}, 'ANCESTOR_XATTR_DENIED')
            if kind == 'file':
                require(value['size'] == 0 and value['sha256'] == EMPTY_SHA, 'POST_CREATE_NONEMPTY_FILE')
                require(value['links'] == 1, 'POST_CREATE_HARDLINK_DENIED')
            else:
                children = sum(v['kind'] == 'directory' and str(PurePosixPath(p).parent) == name
                               for p, v in actual.items())
                require(value['links'] == 2 + children, 'POST_CREATE_DIRECTORY_LINKS_DENIED')
            seen = physical(upper[name], new=True)
            if seen != value:  # metadata only (never contents): kind, mode, owner, size, links, xattr names
                print('POST_CREATE_UPPER_VIEW_DIFF ' + json.dumps({'path': name, 'fields': sorted(
                    k for k in set(seen) | set(value) if seen.get(k) != value.get(k))}), file=sys.stderr)
            require(seen == value, 'POST_CREATE_UPPER_VIEW_DRIFT')
            differences.append({'path': name, 'change': 'mountpoint' if name in targets else 'ancestor',
                                'before': None, 'after': value})
        elif value != old:
            fields = {k for k in set(old) | set(value) if old.get(k) != value.get(k)}
            if (fields == {'links'} and old['kind'] == value['kind'] == 'directory'
                    and value['links'] == 1 and name not in upper):
                # overlayfs reports nlink 1 for a directory merged from several image
                # layers; the single-lower expected view reports the real count. Every
                # child entry is still compared one by one, so no content can hide here.
                continue
            if not (name in copied and old['kind'] == value['kind'] == 'directory' and fields == {'links'} and name in upper):
                # Metadata field names and small scalar values only; never file contents or xattr values.
                small = {k: (old.get(k), value.get(k)) for k in fields if k in ('kind', 'mode', 'uid', 'gid', 'links', 'size')}
                print('POST_CREATE_IMAGE_DIFF ' + json.dumps({'path': name, 'fields': sorted(fields), 'values': small,
                      'copied': name in copied, 'inUpper': name in upper}), file=sys.stderr)
            require(name in copied and old['kind'] == value['kind'] == 'directory'
                    and fields == {'links'} and name in upper, 'POST_CREATE_IMAGE_METADATA_OR_CONTENT_DRIFT')
            children = sum(v['kind'] == 'directory' and
                           ('' if str(PurePosixPath(p).parent) == '.' else str(PurePosixPath(p).parent)) == name
                           for p, v in actual.items() if p)
            require(value['links'] in (1, 2 + children), 'POST_CREATE_DIRECTORY_LINKS_DENIED')
            differences.append({'path': name, 'change': 'copy-up-directory', 'before': old, 'after': value})
    for name, value in upper.items():
        if name in allowed:
            continue
        require(name in copied and name in image and image[name]['kind'] == value['kind'] == 'directory',
                'POST_CREATE_UPPER_ENTRY_TYPE_DENIED')
        require(physical(value).get('xattrs') == image[name].get('xattrs'), 'POST_CREATE_XATTR_DENIED')
        require(all(value[k] == image[name][k] for k in ('mode', 'uid', 'gid')),
                'POST_CREATE_COPYUP_METADATA_DRIFT')
        children = sum(v['kind'] == 'directory' and
                       ('' if str(PurePosixPath(p).parent) == '.' else str(PurePosixPath(p).parent)) == name
                       for p, v in upper.items() if p)
        require(value['links'] == 2 + children, 'POST_CREATE_UPPER_DIRECTORY_LINKS_DENIED')
        if not any(d['path'] == name for d in differences):
            differences.append({'path': name, 'change': 'copy-up-directory',
                                'before': image[name], 'after': actual[name]})
    return sorted(differences, key=lambda d: d['path'])


def correction(image, actual, upper, mounts, kind):
    targets, allowed, _ = mount_targets(mounts, image, kind)
    rows = []
    projected = copy.deepcopy(actual); projected_upper = copy.deepcopy(upper)
    for name in sorted(set(allowed) - set(targets)):
        require(name in upper and name in actual, 'POST_CREATE_MOUNTPOINT_NOT_IN_UPPER')
        value = upper[name]
        require(value['kind'] == actual[name]['kind'] == 'directory', 'ANCESTOR_DIRECTORY_REQUIRED')
        require(value['uid'] == value['gid'] == 0, 'ANCESTOR_OWNER_DENIED')
        require(value.get('xattrs') == {}, 'ANCESTOR_XATTR_DENIED')
        require(value['mode'] in (0o700, 0o711), 'ANCESTOR_MODE_DENIED')
        require(actual[name] == value, 'POST_CREATE_UPPER_VIEW_DRIFT')
        rows.append({'path': name, 'currentMode': value['mode'], 'expectedMode': 0o711})
        projected[name]['mode'] = projected_upper[name]['mode'] = 0o711
    differences = compare_entries(image, projected, projected_upper, mounts, kind)
    return rows, differences


def projected_entries(sealer, path, limits, rows):
    """Run the unchanged historical sealer with only the encoder's mode projected.

    Like rootfs_difference_report.entries, this uses a private globals copy.
    Traversal, content reads, bounds, framing and hash remain historical; this
    is a prediction only. Apply must reproduce it with the unmodified sealer.
    """
    modes = {r['path']: r['expectedMode'] for r in rows}
    original = sealer.__globals__['encoded']
    def encode(item):
        return original(dict(item, mode=modes[item['path']]) if item['path'] in modes else item)
    projected = types.FunctionType(sealer.__code__, {**sealer.__globals__, 'encoded': encode},
                                   sealer.__name__, sealer.__defaults__, sealer.__closure__)
    return projected(path, limits, Budget())


class Docker(V1.Docker):
    def selected(self, role_spec):
        rows = decode(self.read('inspect', role_spec['container_id']))
        require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict,
                'STOPPED_EXACT_CANDIDATE_REQUIRED')
        item = rows[0]
        require(item.get('Id') == role_spec['container_id'] and item.get('Image') == role_spec['image_id'],
                'STOPPED_EXACT_CANDIDATE_REQUIRED')
        stopped(item.get('State'))
        return item  # Full Config/NetworkSettings, including legacy MAC, unchanged.


def stopped(state):
    require(type(state) is dict and state.get('Status') in ('created', 'exited')
            and type(state.get('Pid')) is int and state['Pid'] == 0
            and all(state.get(k) is False for k in ('Running', 'Paused', 'Restarting', 'Dead')),
            'STOPPED_EXACT_CANDIDATE_REQUIRED')


@contextmanager
def directory_fd(path):
    """Walk every physical component from / using O_DIRECTORY | O_NOFOLLOW."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'ABSOLUTE_UPPER_PATH_REQUIRED')
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in path.parts[1:]:
            nested = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = nested
        yield fd
    except OSError:
        raise Denied('ANCESTOR_NOFOLLOW_DIRECTORY_REQUIRED') from None
    finally:
        os.close(fd)


def check_ancestor_fd(fd, row, differences):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0, 'ANCESTOR_OWNER_DENIED')
    require(stat.S_IMODE(info.st_mode) == row['currentMode'] and row['currentMode'] in (0o700, 0o711),
            'ANCESTOR_MODE_DENIED')
    require(not os.listxattr(fd), 'ANCESTOR_XATTR_DENIED')
    # The full difference proof has already excluded undeclared descendants;
    # recheck the immediate names through the held descriptor before fchmod.
    children = {PurePosixPath(d['path']).name for d in differences
                if str(PurePosixPath(d['path']).parent) == row['path']}
    require(set(os.listdir(fd)) == children, 'ANCESTOR_UNDECLARED_CHILD')
    return info


@contextmanager
def correction_fds(plan):
    """Validate BOTH roles and hold all descriptors before the first change."""
    held = []
    with ExitStack() as stack:
        for role in ROLES:
            c = plan['roles'][role]['comparison']
            for row in c['ancestors']:
                path = Path(c['snapshot']['upper']) / row['path']
                fd = stack.enter_context(directory_fd(path))
                info = check_ancestor_fd(fd, row, c['differences'])
                held.append((role, row, fd, info))
        # Catch replacements made while other descriptors were being opened.
        for role, row, fd, before in held:
            c = plan['roles'][role]['comparison']
            with directory_fd(Path(c['snapshot']['upper']) / row['path']) as current:
                require(V1.attributes(os.fstat(current)) == V1.attributes(before)
                        and V1.attributes(check_ancestor_fd(fd, row, c['differences'])) == V1.attributes(before),
                        'ANCESTOR_CHANGED_BEFORE_CHMOD')
        yield held


def chmod_ancestor(fd, row, role, output, progress, chmods):
    """Only called with a descriptor held and validated by correction_fds."""
    if row['currentMode'] == row['expectedMode']:
        return
    progress['phase'] = role + ':CHMOD_ANCESTOR'
    os.fchmod(fd, row['expectedMode'])
    require(stat.S_IMODE(os.fstat(fd).st_mode) == row['expectedMode'], 'ANCESTOR_CHMOD_UNPROVEN')
    change = {'role': role, 'path': row['path'], 'before': row['currentMode'], 'after': row['expectedMode']}
    chmods.append(change)
    # Exclusive incremental evidence retained if a later step fails.
    write_once(output / ('chmod-%03d.json' % len(chmods)), canonical(change))


def corrected_comparison(comparison):
    result = copy.deepcopy(comparison)
    result['currentSeal'] = result['nodeRootfsSeal'] = result['expectedSeal']
    result['upperSeal'] = result['expectedUpperSeal']
    for row in result['ancestors']:
        row['currentMode'] = row['expectedMode']
    return result


def source_kind(path):
    path = V1.absolute(path); ancestors(path)
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode), 'OCI_BIND_SOURCE_TYPE_DENIED')
    return 'file' if stat.S_ISREG(info.st_mode) else 'directory' if stat.S_ISDIR(info.st_mode) else 'special'


def mount_rows(raw=None):
    if raw is None:
        with open('/proc/self/mountinfo', 'rb') as stream:
            raw = stream.read(1048577)
    require(len(raw) <= 1048576, 'MOUNTINFO_UNBOUNDED')
    rows = []
    for line in raw.decode('ascii').splitlines():
        left, right = line.split(' - '); left = left.split(); right = right.split()
        # Restrict profile instead of ambiguously decoding escaped option paths.
        rows.append({'target': left[4], 'options': left[5].split(','),
                     'type': right[0], 'super': right[2].split(',')})
    return rows


SYSTEM_CONTAINERD_SNAPSHOTS = Path('/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots')


def overlay_binding(root, docker_root):
    rows = mount_rows(); root = str(root)
    selected = [r for r in rows if r['target'] == root]
    require(len(selected) == 1 and selected[0]['type'] == 'overlay', 'OCI_ROOT_OVERLAY_REQUIRED')
    require(not any(r['target'].startswith(root + '/') for r in rows), 'OCI_ROOT_SUBMOUNT_DENIED')
    opts = {}
    for option in selected[0]['super']:
        key, sep, value = option.partition('=')
        require(key not in opts, 'OVERLAY_OPTION_DUPLICATE')
        opts[key] = value if sep else True
    require(all(k in opts for k in ('upperdir', 'lowerdir', 'workdir')), 'CONTAINERD_SNAPSHOT_MOUNT_REQUIRED')
    # Docker-managed containerd keeps snapshots under the Docker root; a host
    # (system) containerd, as on the VPS with Docker 29, under /var/lib/containerd.
    bases = (docker_root / 'containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots',
             SYSTEM_CONTAINERD_SNAPSHOTS)
    paths = [opts['upperdir'], opts['workdir'], *opts['lowerdir'].split(':')]
    require(3 <= len(paths) <= 258 and len(set(paths)) == len(paths), 'SNAPSHOT_LAYERS_REQUIRED')
    used = set()
    for value in paths:
        path = V1.absolute(value); ancestors(path)
        require(path.parent.parent in bases and path.parent.name.isdecimal()
                and path.name in ('fs', 'work') and path.is_dir() and not path.is_symlink(),
                'CONTAINERD_SNAPSHOT_PATH_REQUIRED')
        used.add(path.parent.parent)
    require(len(used) == 1, 'CONTAINERD_SNAPSHOT_ROOT_MIXED')
    require(Path(opts['upperdir']).name == 'fs' and Path(opts['workdir']).name == 'work'
            and Path(opts['upperdir']).parent == Path(opts['workdir']).parent
            and all(Path(p).name == 'fs' for p in opts['lowerdir'].split(':')), 'SNAPSHOT_LAYOUT_REQUIRED')
    return {'root': root, 'type': selected[0]['type'], 'options': sorted(selected[0]['super']),
            'upper': opts['upperdir'], 'lowers': opts['lowerdir'].split(':'), 'work': opts['workdir']}


def empty_mountpoint(path):
    ancestors(path); info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700 and not list(path.iterdir())
            and not os.path.ismount(path), 'PREEXISTING_EMPTY_PRIVATE_MOUNTPOINT_REQUIRED')
    require(not any(r['target'] == str(path) or r['target'].startswith(str(path) + '/') for r in mount_rows()),
            'VIEW_ALREADY_MOUNTED')


def run_mount(args, command, unmount=False):
    binding = (args.umount, args.umount_sha256) if unmount else (args.mount, args.mount_sha256)
    program(*binding)
    subprocess.run([str(binding[0]), *command], check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
                   env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    program(*binding)


def verified_root_mode(layout, image_id):
    """Authenticate retained layer bytes before the historical header reader.

    The v1 helper checks the manifest digest but assumes freshly verified
    layout blobs. Here the retained blobs must be checked again, read-only.
    """
    manifest = layout / 'blobs/sha256' / image_id[7:]
    raw = private(manifest)
    require('sha256:' + sha(raw) == image_id, 'ROOT_MODE_MANIFEST_DRIFT')
    layers = decode(raw)['layers']
    require(type(layers) is list and 1 <= len(layers) <= 128, 'ROOT_MODE_LAYERS_UNBOUNDED')
    bindings = [{'path': str(manifest), 'sha256': sha(raw)}]
    for layer in layers:
        digest = layer['digest']
        require(type(digest) is str and re.fullmatch('sha256:[0-9a-f]{64}', digest), 'LAYER_DIGEST_REQUIRED')
        path = layout / 'blobs/sha256' / digest[7:]
        V1.frozen_archive(path, digest[7:])
        bindings.append({'path': str(path), 'sha256': digest[7:]})
    policy = V1.expected_root_mode(layout, image_id)
    for binding in bindings:
        V1.frozen_archive(Path(binding['path']), binding['sha256'])
    return policy, bindings


@contextmanager
def readonly_view(args, source, target, image=False):
    empty_mountpoint(target)
    if image:
        # A lower-only overlay is refused by the VPS kernel (exit 32) and an overlay
        # with an upper cannot be remounted ro. Reuse the v1 expected_overlay (empty
        # upper, root attributes copied from the offline tree, exercised on the VPS
        # on 2026-11-13): the image view is only read, and the upper is proven still
        # empty afterwards (IMAGE_VIEW_UPPER_WRITTEN), so nothing reached the image.
        try:
            with V1.expected_overlay(source, target, (args.mount, args.mount_sha256),
                                     (args.umount, args.umount_sha256)) as view:
                yield view
        finally:
            require(not any(r['target'].startswith(str(target) + '/') for r in mount_rows()), 'IMAGE_VIEW_STILL_MOUNTED')
            upper = target / 'upper'
            require(not upper.exists() or not list(upper.iterdir()), 'IMAGE_VIEW_UPPER_WRITTEN')
            for name in ('view', 'upper', 'work'):
                path = target / name
                if path.exists():
                    for child in sorted(path.rglob('*'), key=lambda c: len(c.parts), reverse=True):
                        require(child.is_dir() and not child.is_symlink(), 'IMAGE_VIEW_SCRATCH_UNEXPECTED')
                        child.rmdir()
                    path.rmdir()
            empty_mountpoint(target)
        return
    mounted = False
    try:
        run_mount(args, ['-n', '--bind', str(source), str(target)])
        mounted = True
        run_mount(args, ['-n', '-o', 'remount,bind,ro', str(target)])
        rows = [r for r in mount_rows() if r['target'] == str(target)]
        require(len(rows) == 1 and 'ro' in rows[0]['options'], 'READONLY_VIEW_UNPROVEN')
        yield target
    finally:
        # A mount can have succeeded even if the post-command binary hash
        # check failed. The target was proven unmounted before this attempt.
        if mounted or any(r['target'] == str(target) for r in mount_rows()):
            run_mount(args, ['-n', str(target)], unmount=True)
            require(not os.path.ismount(target), 'READONLY_VIEW_RETAINED')


def compare_role(args, docker, role, previous, inputs, baselines, sealer):
    rf = previous['roles'][role]
    image_receipt = binding_document(rf['offlineImageReceipt'], inputs)
    receipt = binding_document(rf['offlineDockerReceipt'], inputs)
    binding_document(rf['comparison'], inputs)
    require(image_receipt['schema'] == 'ouf.semantic-offline-image-rootfs.v1'
            and receipt['schema'] == 'ouf.semantic-offline-docker-rootfs.v1'
            and receipt['imageReceiptSha256'] == rf['offlineImageReceipt']['sha256']
            and receipt['imageRootfsSeal'] == image_receipt['rootfsSeal']
            and receipt['manifestDigest'] == image_receipt['manifestDigest'] == rf['imageId']
            and receipt['sourceManifestSha256'] == args.source_manifest_sha256
            and receipt['engineCommit'] == previous['engine']['commit'], 'OFFLINE_RECEIPTS_DRIFT')
    offline = Path(rf['offlineDockerReceipt']['path']).parent / 'bundle/rootfs'
    policy = bound(getattr(args, role + '_frame_policy'), getattr(args, role + '_frame_policy_sha256'), inputs)
    oci = bound(getattr(args, role + '_oci_config'), getattr(args, role + '_oci_config_sha256'), inputs)
    require(oci == policy['expectedOci'], 'DOCKER_OCI_FRAME_DRIFT')
    # Docker 29 containerd emits an absolute host root.path, not /proc/PID/root
    # and not the runtime namespace populated with bind/tmpfs contents.
    root = args.docker_root / 'rootfs/overlayfs' / rf['containerId']
    require(oci['root']['path'] == str(root), 'OCI_ROOT_PATH_NOT_DOCKER_CONTAINERD')
    limits = receipt['rootfsLimits']
    require(limits == image_receipt['rootfsLimits'], 'ROOTFS_LIMITS_DRIFT')
    require(sealer(offline, limits, Budget()) == receipt['rootfsSeal'], 'OFFLINE_EXPECTATION_CHANGED')
    with readonly_view(args, offline, getattr(args, role + '_image_view'), image=True) as image_view:
        image_seal, image = entries(sealer, image_view, limits)
        # Umoci's bundle wrapper mode is not necessarily the layer root mode.
        # Reuse the v1 independent image-header policy; never choose from actual.
        root_policy, root_mode_inputs = verified_root_mode(Path(rf['offlineDockerReceipt']['path']).parent / 'layout', rf['imageId'])
        image = {p: dict(v) for p, v in image.items()}
        image['']['mode'] = root_policy['mode']
        with V1.checked_export(args, docker, role, baselines) as mounted:
            require(mounted == root, 'EXPORT_NOT_OCI_ROOT')
            snapshot = overlay_binding(root, args.docker_root)
            upper_seal, upper = entries(sealer, Path(snapshot['upper']), limits)
            with readonly_view(args, mounted, getattr(args, role + '_container_view')) as view:
                actual_seal, actual = entries(sealer, view, limits)
                rows, differences = correction(image, actual, upper, oci['mounts'], source_kind)
                expected_seal = projected_entries(sealer, view, limits, rows)
                expected_upper_seal = projected_entries(sealer, Path(snapshot['upper']), limits, rows)
                # Same function and same path resolution as NodeObservation.observe.
                direct, direct_entries = entries(sealer, Path(oci['root']['path']), limits)
                require(actual_seal == direct and actual == direct_entries, 'NODE_ROOTFS_VIEW_MISMATCH')
                require(entries(sealer, view, limits) == (actual_seal, actual), 'POST_CREATE_ROOTFS_CHANGED')
            require(overlay_binding(root, args.docker_root) == snapshot
                    and entries(sealer, Path(snapshot['upper']), limits) == (upper_seal, upper),
                    'SNAPSHOT_CHANGED_DURING_OBSERVATION')
        require(sealer(image_view, limits, Budget()) == image_seal, 'OFFLINE_EXPECTATION_CHANGED')
    require(sealer(offline, limits, Budget()) == receipt['rootfsSeal'], 'OFFLINE_EXPECTATION_CHANGED')
    for binding in root_mode_inputs:
        V1.frozen_archive(Path(binding['path']), binding['sha256'])
    return {'schema': 'ouf.semantic-provider-b1-post-create-comparison.v1', 'role': role,
            'containerId': rf['containerId'], 'imageId': rf['imageId'], 'snapshot': snapshot,
            'framePolicy': {'path': str(getattr(args, role + '_frame_policy')),
                            'sha256': getattr(args, role + '_frame_policy_sha256')},
            'ociConfig': {'path': str(getattr(args, role + '_oci_config')),
                          'sha256': getattr(args, role + '_oci_config_sha256')},
            'oldSeal': V1.effective_seal(rf['effectiveSeal']), 'imageOverlaySeal': image_seal,
            'expectedRootMode': root_policy,
            'rootModeInputBindings': root_mode_inputs,
            'rule': RULE, 'ancestors': rows, 'currentSeal': actual_seal,
            'expectedSeal': expected_seal, 'expectedUpperSeal': expected_upper_seal,
            'effectiveSeal': V1.effective_seal(expected_seal), 'nodeRootfsSeal': direct,
            'nodeRootfsPath': str(root), 'nodeViewMatches': True, 'upperSeal': upper_seal,
            'differences': differences, 'privateMountContentsRead': False}


def observe(args, docker, allow_output=False):
    output = OUTPUT_PARENT / ('semantic-provider-b1-rootfs-' + args.date + '-mountpoint-0711')
    ancestors(output)
    if not allow_output:
        require(not os.path.lexists(output), 'NEW_OUTPUT_DIRECTORY_REQUIRED')
    inputs = {}
    previous = bound(args.previous_result, args.previous_result_sha256, inputs)
    require(previous['schema'] == SCHEMA and previous['status'] == PREPARED
            and set(previous['roles']) == set(ROLES)
            and previous['sourceManifestSha256'] == args.source_manifest_sha256, 'PREVIOUS_ROOTFS_RESULT_REQUIRED')
    successors = bound(args.a_successors, args.a_successors_sha256, inputs)
    require(previous['aSuccessors'] == {'path': str(args.a_successors), 'sha256': args.a_successors_sha256},
            'A_SUCCESSOR_BINDING_MISMATCH')
    require(previous['engine']['version'] == '29.8.1' and previous['engine']['commit'] == V1.SUPPORTED_INIT_COMMIT,
            'EXACT_OBSERVED_ENGINE_SOURCE_REQUIRED')
    info = decode(docker.read('info', '--format', '{{json .}}'))
    version = decode(docker.read('version', '--format', '{{json .Server}}'))
    require(info['ServerVersion'] == version['Version'] == previous['engine']['version']
            and version['GitCommit'] == previous['engine']['serverGitCommit']
            and info['Driver'] == previous['engine']['storageDriver'] == 'overlayfs'
            and info['DockerRootDir'] == str(args.docker_root), 'ENGINE_BINDING_DRIFT')
    for name in ('docker', 'mount', 'umount'):
        program(getattr(args, name), getattr(args, name + '_sha256'))
    views = [getattr(args, r + '_' + n) for r in ROLES for n in ('image_view', 'container_view')]
    roots = [args.docker_root / 'rootfs/overlayfs' / previous['roles'][r]['containerId'] for r in ROLES]
    protected = [args.source, args.previous_result.parent, args.docker_root, output]
    require(len(set(views)) == 4 and all(not any(v == p or p in v.parents or v in p.parents
            for p in protected + roots + [w for w in views if w != v]) for v in views), 'VIEW_PATH_OVERLAP_DENIED')
    for view in views:
        empty_mountpoint(view)
    for role in ROLES:
        row = previous['roles'][role]
        require(re.fullmatch('[0-9a-f]{64}', row['containerId']) and
                re.fullmatch('sha256:[0-9a-f]{64}', row['imageId']), 'EXACT_CANDIDATE_REQUIRED')
        setattr(args, role + '_container_id', row['containerId'])
        setattr(args, role + '_image_id', row['imageId'])
        # checked_export and unchanged_candidate use the v1 role accessor.
        for key in ('archive', 'archive_sha256', 'config_digest'):
            setattr(args, role + '_' + key, None)
    require(previous['roles']['adapter']['containerId'] != previous['roles']['southbound']['containerId']
            and [(r['containerId'], r['image']) for r in successors['containers']] ==
            [(previous['roles'][r]['containerId'], previous['roles'][r]['imageId']) for r in ROLES],
            'A_SUCCESSOR_BINDING_MISMATCH')
    states = docker.states()
    baselines = {r: docker.selected(V1.spec(args, r)) for r in ROLES}
    require(all(previous['roles'][r]['containerId'] in states for r in ROLES), 'STATE_INVENTORY_UNPROVEN')
    for r in ROLES:
        stopped(states[previous['roles'][r]['containerId']])
    sealer = load_sealer(args.source, args.source_manifest_sha256)
    try:
        comparisons = {r: compare_role(args, docker, r, previous, inputs, baselines, sealer) for r in ROLES}
    finally:
        require(docker.states() == states, 'EXISTING_CONTAINER_STATES_CHANGED')
        for role in ROLES:
            V1.unchanged_candidate(docker, V1.spec(args, role), baselines[role])
    for path, digest in list(inputs.items()):
        require(sha(private(Path(path))) == digest, 'INPUT_CHANGED_DURING_OBSERVATION')
    load_sealer(args.source, args.source_manifest_sha256)
    binaries = {}
    for name in ('docker', 'mount', 'umount'):
        path, digest = getattr(args, name), getattr(args, name + '_sha256')
        program(path, digest); binaries[name] = {'path': str(path), 'sha256': digest}
    return {'schema': 'ouf.semantic-provider-b1-rootfs-plan.v3', 'rule': RULE, 'method': 'checked-export-readonly-bind',
            'previousResult': {'path': str(args.previous_result), 'sha256': args.previous_result_sha256},
            'aSuccessors': previous['aSuccessors'], 'engine': previous['engine'], 'inputs': inputs,
            'source': {'path': str(args.source), 'manifestSha256': args.source_manifest_sha256},
            'binaries': binaries, 'containerStatesSha256': sha(canonical(states)),
            'candidateSha256': {r: sha(canonical(baselines[r])) for r in ROLES},
            'views': {r: {n: str(getattr(args, r + '_' + n)) for n in ('image_view', 'container_view')} for r in ROLES},
            'roles': {r: {'containerId': previous['roles'][r]['containerId'],
                         'imageId': previous['roles'][r]['imageId'],
                         'offlineImageReceipt': previous['roles'][r]['offlineImageReceipt'],
                         'offlineDockerReceipt': previous['roles'][r]['offlineDockerReceipt'],
                         'comparison': comparisons[r]} for r in ROLES},
            'output': str(output), 'plannedWrites': ['chmod-NNN.json (per chmod)', 'adapter-comparison.json', 'southbound-comparison.json', 'result.json'],
            'stoppedContainerExports': 2, 'applyStoppedContainerExports': 6,
            'containerLifecycleOperations': 0, 'dockerStartRequests': 0, 'doNotRerunApply': True}


def make_result(plan, comparisons, chmods):
    return {'schema': SCHEMA, 'status': PREPARED, 'planSha256': sha(canonical(plan)),
            'aSuccessors': plan['aSuccessors'], 'sourceManifestSha256': plan['source']['manifestSha256'],
            'engine': plan['engine'], 'previousResult': plan['previousResult'], 'rule': RULE,
            'chmods': chmods,
            'roles': {r: {**{k: plan['roles'][r][k] for k in
                            ('containerId', 'imageId', 'offlineImageReceipt', 'offlineDockerReceipt')},
                         'comparison': comparisons[r], 'effectiveSeal': plan['roles'][r]['comparison']['effectiveSeal']}
                      for r in ROLES},
            'containerLifecycleOperations': 0, 'dockerStartRequests': 0, 'stoppedContainerExports': 6,
            'privateKeysRead': 0, 'signaturesIssued': 0, 'startAuthorized': False,
            'acceptanceGranted': False, 'doNotRerunApply': True}


def apply_plan(args, docker, plan, progress):
    require(args.plan_sha256 == sha(canonical(plan)), 'PLAN_DIGEST_CHANGED')
    output = Path(plan['output'])
    progress['phase'] = 'CREATE_OUTPUT'
    output.mkdir(mode=0o700)  # Exclusive: no rollback or removal of partial evidence.
    progress['created'] = True
    progress['phase'] = 'FINAL_REVALIDATION'
    require(observe(args, docker, allow_output=True) == plan, 'PLAN_CHANGED_BEFORE_WRITE')
    chmods = []
    with correction_fds(plan) as held:
        # Inventory and complete candidates are checked immediately before writes.
        states = docker.states()
        require(sha(canonical(states)) == plan['containerStatesSha256'], 'EXISTING_CONTAINER_STATES_CHANGED')
        for role in ROLES:
            stopped(states[plan['roles'][role]['containerId']])
            require(sha(canonical(docker.selected(V1.spec(args, role)))) == plan['candidateSha256'][role],
                    'STOPPED_CANDIDATE_CONFIGURATION_CHANGED')
        for role, row, fd, before in held:
            if row['currentMode'] == row['expectedMode']:
                continue
            chmod_ancestor(fd, row, role, output, progress, chmods)
    progress['phase'] = 'POST_CHMOD_REVALIDATION'
    final = observe(args, docker, allow_output=True)
    expected = copy.deepcopy(plan)
    for role in ROLES:
        expected['roles'][role]['comparison'] = corrected_comparison(plan['roles'][role]['comparison'])
    require(final == expected, 'POST_CHMOD_PLAN_MISMATCH')
    comparisons = {}
    for role in ROLES:
        progress['phase'] = role + ':WRITE_COMPARISON'
        path = output / (role + '-comparison.json')
        raw = canonical(final['roles'][role]['comparison'])
        write_once(path, raw)
        comparisons[role] = {'path': str(path), 'sha256': sha(raw)}
    result = make_result(plan, comparisons, chmods)
    progress['phase'] = 'WRITE_RESULT'
    write_once(output / 'result.json', canonical(result))
    progress['phase'] = 'COMPLETE'
    return result


def main(argv=None):
    args = arguments(argv); progress = {'phase': 'PREFLIGHT', 'created': False}
    try:
        require(sys.platform == 'linux' and os.geteuid() == os.getegid() == 0
                and sys.flags.isolated and sys.dont_write_bytecode, 'ISOLATED_ROOT_REQUIRED')
        os.umask(0o077)
        # Resolve transport only from the hash-bound historical result.
        previous = bound(args.previous_result, args.previous_result_sha256, {})
        args.docker_root = V1.absolute(previous['engine']['dockerRoot'])
        args.docker_socket = previous['engine']['dockerSocket']
        require(args.docker_socket.startswith('unix:///'), 'LOCAL_DOCKER_SOCKET_REQUIRED')
        V1.absolute(args.docker_socket[len('unix://'):])
        args.output_root = OUTPUT_PARENT
        args.output_name = 'semantic-provider-b1-rootfs-' + args.date + '-mountpoint-0711'
        docker = Docker(args)
        # The v1 plan never exported; v2 compares (and so exports) in plan too.
        # Point the Docker CLI at an absent leaf inside a fresh private 0700
        # directory beside the views, so no operator config/plugins are read.
        scratch = Path(tempfile.mkdtemp(prefix='docker-config.', dir=str(args.adapter_image_view.parent)))
        try:
            os.chmod(scratch, 0o700)
            docker.config = scratch / 'config'
            plan = observe(args, docker)
            result = ({'status': 'SEMANTIC_PROVIDER_B1_ROOTFS_PLAN', 'plan': plan, 'planSha256': sha(canonical(plan))}
                      if args.plan else apply_plan(args, docker, plan, progress))
        finally:
            shutil.rmtree(scratch, ignore_errors=False)
        print(canonical(result).decode(), flush=True)
        return 0
    except Exception as error:
        historical_denial = type(error).__name__ == 'PreexecDenied' and str(error).startswith('ROOTFS_')
        reason = str(error) if (isinstance(error, Denied) or historical_denial) and re.fullmatch('[A-Z0-9_]{1,80}', str(error)) else 'B1_ROOTFS_V3_UNPROVEN'
        print(canonical({'status': 'HELD', 'reason': reason, 'phase': progress['phase'],
                         'outputDirectory': str(OUTPUT_PARENT / ('semantic-provider-b1-rootfs-' + args.date + '-mountpoint-0711')),
                         'outputCreated': progress['created'], 'partialDirectoriesRetained': progress['created'],
                         'automaticRollback': False, 'doNotRerunApply': True}).decode(), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
