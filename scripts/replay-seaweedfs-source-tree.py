#!/usr/bin/env python3
"""Compute a patched Git tree without a working-tree scan or caller-index mutation."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile


class ReplayError(RuntimeError):
    pass


def git(args, *, cwd=None, env=None):
    result = subprocess.run(['git', *args], cwd=cwd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise ReplayError('git ' + ' '.join(args[:3]) + ': ' + result.stderr.decode(errors='replace'))
    return result.stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replay(repository, manifest_path, patch_root, work_parent, base=None):
    repository, patch_root = Path(repository).resolve(), Path(patch_root).resolve()
    manifest_path, work_parent = Path(manifest_path), Path(work_parent)
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    base = base or manifest['upstreamCommit']
    patches = manifest['orderedPatches']
    if not isinstance(base, str) or base.startswith('-'):
        raise ReplayError('invalid base revision')
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
    # Resolve from the caller repository without modifying its index, refs or objects.
    base_tree = git(['rev-parse', '--verify', base + '^{tree}'], cwd=repository, env=env).decode().strip()
    object_format = git(['rev-parse', '--show-object-format'], cwd=repository, env=env).decode().strip()
    object_path = Path(git(['rev-parse', '--git-path', 'objects'], cwd=repository, env=env).decode().strip())
    if not object_path.is_absolute():
        object_path = repository / object_path
    object_path = object_path.resolve()
    if '\n' in str(object_path) or '\r' in str(object_path):
        raise ReplayError('unsupported object-directory path')
    validated = []
    for item in patches:
        relative = PurePosixPath(item['path'])
        if relative.is_absolute() or '..' in relative.parts or not relative.parts:
            raise ReplayError('patch path must stay inside patch root')
        path = (patch_root / relative).resolve()
        if not path.is_relative_to(patch_root):
            raise ReplayError('patch symlink escapes patch root')
        data = path.read_bytes()
        if not re.fullmatch('[0-9a-f]{64}', item['sha256']) or sha(data) != item['sha256']:
            raise ReplayError('patch SHA256 mismatch: ' + item['path'])
        validated.append((item, data))
    work_parent.mkdir(parents=True, exist_ok=True)
    # A private object database writes new blobs/trees locally and only reads the
    # source object database through alternates. No source .git files are written.
    with tempfile.TemporaryDirectory(prefix='canonical-tree-', dir=work_parent) as temporary:
        temporary = Path(temporary)
        private_git = temporary / 'objects.git'
        git(['init', '--bare', '--object-format=' + object_format, str(private_git)], env=env)
        (private_git / 'objects/info/alternates').write_text(str(object_path) + '\n')
        env.update(GIT_DIR=str(private_git), GIT_INDEX_FILE=str(temporary / 'index'))
        git(['read-tree', base_tree], env=env)
        steps = []
        for number, (item, data) in enumerate(validated, 1):
            # Copy already-verified bytes into owned scratch; no TOCTOU re-read of
            # the caller's patch path between hash verification and application.
            local_patch = temporary / ('patch-' + str(number))
            local_patch.write_bytes(data)
            git(['apply', '--cached', '--whitespace=nowarn', str(local_patch)], env=env)
            tree = git(['write-tree'], env=env).decode().strip()
            steps.append({'number': number, 'path': item['path'],
                          'sha256': item['sha256'], 'resultTree': tree})
        tree = git(['write-tree'], env=env).decode().strip()
        entries = git(['ls-tree', '-rz', '--full-tree', tree], env=env)
        return {'schema': 'ouf.canonical-source-tree-replay.v1',
                'method': 'read-tree base; exact ordered patches via git apply --cached in private object database/index',
                'manifestSha256': sha(manifest_bytes), 'baseRevision': base,
                'baseTree': base_tree, 'objectFormat': object_format,
                'orderedPatchCount': len(steps), 'steps': steps,
                'patchedSourceTree': tree, 'treeEntryCount': len(entries.split(b'\0')) - 1,
                'gitLsTreeZSha256': sha(entries),
                'callerIndexRefsObjectsUntouched': True}, entries


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True, type=Path)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--patch-root', required=True, type=Path)
    parser.add_argument('--base', help='explicit commit/tree base; defaults to manifest upstreamCommit')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--entries-output', type=Path, help='optional raw NUL-delimited git ls-tree entries')
    parser.add_argument('--work-parent', type=Path, help='owned scratch parent; defaults to output directory')
    args = parser.parse_args()
    try:
        receipt, entries = replay(args.repository, args.manifest, args.patch_root,
                                  args.work_parent or args.output.parent, args.base)
    except (ReplayError, KeyError, ValueError, OSError) as error:
        parser.exit(1, str(error) + '\n')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    if args.entries_output:
        args.entries_output.parent.mkdir(parents=True, exist_ok=True)
        args.entries_output.write_bytes(entries)
    print(receipt['patchedSourceTree'])
