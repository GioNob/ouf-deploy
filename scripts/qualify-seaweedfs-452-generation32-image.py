#!/usr/bin/env python3
"""Exact generation32 image qualification; no inherited generation31 outcomes."""
import importlib.util
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
ENGINE_PATH = 'tools/storage_security/generation_image_v3.py'
spec = importlib.util.spec_from_file_location('generation32_image_engine', ROOT / ENGINE_PATH)
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)
MANIFEST_PATH = 'releases/seaweedfs-452-generation32-build-manifest-20261103.json'
engine.configure(ROOT, 32, MANIFEST_PATH, (
    '.github/workflows/storage-452-generation32-image.yml',
    'scripts/qualify-seaweedfs-452-generation32-image.py',
    'scripts/readback-seaweedfs-452-generation32-image.py',
    ENGINE_PATH, 'tools/storage_security/generation_readback_v1.py',
    'scripts/assess-storage-sdk-lifecycle.py', 'tools/storage_security/runtime_image.py',
    'scripts/assess-storage-runtime-image-20261102.py',
    'scripts/qualify-seaweedfs-raftstore-compat.py',
    'tests/fixtures/seaweedfs-raftstore-compat/compat_test.go',
    'tests/test_seaweedfs_452_generation32_image.py',
    'tests/test_storage_runtime_image.py',
    'scripts/replay-seaweedfs-source-tree.py', 'tests/test_replay_seaweedfs_source_tree.py', MANIFEST_PATH,
), 'releases/seaweedfs-452-generation31-build-manifest-20261103.json',
    '9a2a00893a07a33e432ac35f6d06da79fd27181ebf16d2fbc4b45f5f9e697719')
if __name__ == '__main__':
    engine.main()
