import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/replay-seaweedfs-source-tree.py'
spec = importlib.util.spec_from_file_location('canonical_replay', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CanonicalTreeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_TMPDIR'))
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '--initial-branch=main')
        self.git('config', 'user.name', 'OUF fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'core.filemode', 'true')
        (self.repo / '.gitignore').write_text('*.bin\nignored/\n')
        (self.repo / 'keep.bin').write_bytes(b'upstream tracked ignored\x00bytes')
        (self.repo / 'ignored').mkdir()
        (self.repo / 'ignored/keep.txt').write_text('also tracked upstream\n')
        (self.repo / 'normal.txt').write_text('before\n')
        (self.repo / 'run.sh').write_text('#!/bin/sh\nexit 0\n')
        (self.repo / 'run.sh').chmod(0o755)
        (self.repo / 'link').symlink_to('keep.bin')
        self.git('add', '-f', '.')
        self.git('-c', 'commit.gpgsign=false', 'commit', '-m', 'upstream fixture')
        self.base = self.git('rev-parse', 'HEAD').decode().strip()
        (self.repo / 'normal.txt').write_text('after\n')
        (self.repo / 'new.sh').write_text('#!/bin/sh\nexit 1\n')
        (self.repo / 'new.sh').chmod(0o755)
        self.git('add', '--intent-to-add', 'new.sh')
        self.patch = self.root / 'change.patch'
        self.patch.write_bytes(self.git('diff', '--binary', '--full-index'))
        self.manifest = self.root / 'manifest.json'
        self.write_manifest(self.patch)
        self.work = self.root / 'owned-work'
        self.work.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args, env=None):
        return subprocess.check_output(['git', *args], cwd=self.repo,
                                       env=env, stderr=subprocess.PIPE)

    def write_manifest(self, patch):
        self.manifest.write_text(json.dumps({'upstreamCommit': self.base,
            'orderedPatches': [{'path': patch.name,
                               'sha256': hashlib.sha256(patch.read_bytes()).hexdigest()}]}))

    def snapshot(self):
        return {str(p.relative_to(self.repo)): ('symlink', os.readlink(p)) if p.is_symlink()
                else (p.stat().st_mode, hashlib.sha256(p.read_bytes()).hexdigest())
                for p in self.repo.rglob('*') if p.is_file() or p.is_symlink()}

    def replay(self, base=None):
        return module.replay(self.repo, self.manifest, self.root, self.work, base)

    @staticmethod
    def entries(raw):
        result = {}
        for line in raw.split(b'\0'):
            if line:
                metadata, path = line.split(b'\t', 1)
                mode, kind, oid = metadata.decode().split()
                result[path.decode()] = (mode, kind, oid)
        return result

    def test_preserves_tracked_ignored_files_executable_and_symlink_modes(self):
        before = self.snapshot()
        result, raw = self.replay()
        entries = self.entries(raw)
        self.assertEqual(set(entries), {'.gitignore', 'keep.bin', 'ignored/keep.txt',
                                      'normal.txt', 'run.sh', 'new.sh', 'link'})
        self.assertEqual(entries['run.sh'][0], '100755')
        self.assertEqual(entries['new.sh'][0], '100755')
        self.assertEqual(entries['link'][0], '120000')
        self.assertEqual(entries['keep.bin'][2], self.git('rev-parse', 'HEAD:keep.bin').decode().strip())
        self.assertEqual(result['treeEntryCount'], 7)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(list(self.work.iterdir()), [])

    def test_regression_empty_index_scan_drops_tracked_ignored_files(self):
        env = os.environ.copy()
        env['GIT_INDEX_FILE'] = str(self.root / 'incorrect-empty-index')
        self.git('read-tree', '--empty', env=env)
        self.git('add', '-A', env=env)
        incorrect = self.git('write-tree', env=env).decode().strip()
        incorrect_entries = self.entries(self.git('ls-tree', '-rz', incorrect))
        self.assertNotIn('keep.bin', incorrect_entries)
        self.assertNotIn('ignored/keep.txt', incorrect_entries)
        result, raw = self.replay()
        self.assertNotEqual(result['patchedSourceTree'], incorrect)
        self.assertIn('keep.bin', self.entries(raw))

    def test_commit_and_parent_tree_bases_are_equivalent(self):
        commit_result, _ = self.replay()
        tree = self.git('rev-parse', 'HEAD^{tree}').decode().strip()
        tree_result, _ = self.replay(tree)
        self.assertEqual(commit_result['patchedSourceTree'], tree_result['patchedSourceTree'])

    def test_wrong_hash_fails_without_mutating_caller_or_leaving_scratch(self):
        data = json.loads(self.manifest.read_text())
        data['orderedPatches'][0]['sha256'] = '0' * 64
        self.manifest.write_text(json.dumps(data))
        before = self.snapshot()
        with self.assertRaisesRegex(module.ReplayError, 'SHA256 mismatch'):
            self.replay()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(list(self.work.iterdir()), [])

    def test_unapplicable_patch_fails_closed_and_preserves_caller(self):
        self.patch.write_text('diff --git a/normal.txt b/normal.txt\n--- a/normal.txt\n+++ b/normal.txt\n@@ -1 +1 @@\n-not present\n+after\n')
        self.write_manifest(self.patch)
        before = self.snapshot()
        with self.assertRaises(module.ReplayError):
            self.replay()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(list(self.work.iterdir()), [])

    def test_path_escape_rejected_before_apply(self):
        data = json.loads(self.manifest.read_text())
        data['orderedPatches'][0]['path'] = '../outside.patch'
        self.manifest.write_text(json.dumps(data))
        before = self.snapshot()
        with self.assertRaisesRegex(module.ReplayError, 'inside patch root'):
            self.replay()
        self.assertEqual(before, self.snapshot())

    def test_ordered_patch_chain_is_not_reordered(self):
        second = self.root / 'second.patch'
        second.write_text('diff --git a/normal.txt b/normal.txt\n--- a/normal.txt\n+++ b/normal.txt\n@@ -1 +1 @@\n-after\n+last\n')
        data = json.loads(self.manifest.read_text())
        data['orderedPatches'].append({'path': second.name, 'sha256': hashlib.sha256(second.read_bytes()).hexdigest()})
        self.manifest.write_text(json.dumps(data))
        before = self.snapshot()
        result, raw = self.replay()
        self.assertEqual(result['orderedPatchCount'], 2)
        self.assertEqual(self.entries(raw)['normal.txt'][2], hashlib.sha1(b'blob 5\x00last\n').hexdigest())
        data['orderedPatches'].reverse()
        self.manifest.write_text(json.dumps(data))
        with self.assertRaises(module.ReplayError):
            self.replay()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(list(self.work.iterdir()), [])

    def test_inherited_git_index_does_not_redirect_private_replay(self):
        caller_index = self.repo / '.git/index'
        previous = os.environ.get('GIT_INDEX_FILE')
        os.environ['GIT_INDEX_FILE'] = str(caller_index)
        before = self.snapshot()
        try:
            result, _ = self.replay()
        finally:
            if previous is None:
                os.environ.pop('GIT_INDEX_FILE', None)
            else:
                os.environ['GIT_INDEX_FILE'] = previous
        self.assertEqual(result['treeEntryCount'], 7)
        self.assertEqual(before, self.snapshot())


if __name__ == '__main__':
    unittest.main(verbosity=2)
