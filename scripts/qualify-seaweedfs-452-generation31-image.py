#!/usr/bin/env python3
"""Exact generation31 image qualification; no inherited generation30 outcomes."""
import importlib.util
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
ENGINE_PATH = 'tools/storage_security/generation_image_v2.py'
spec = importlib.util.spec_from_file_location('generation31_image_engine', ROOT / ENGINE_PATH)
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)
MANIFEST_PATH = 'releases/seaweedfs-452-generation31-build-manifest-20261103.json'
engine.configure(ROOT, 31, MANIFEST_PATH, (
    '.github/workflows/storage-452-generation31-image.yml',
    'scripts/qualify-seaweedfs-452-generation31-image.py',
    'scripts/readback-seaweedfs-452-generation31-image.py',
    ENGINE_PATH, 'tools/storage_security/generation_readback_v1.py',
    'scripts/assess-storage-sdk-lifecycle.py', 'tools/storage_security/runtime_image.py',
    'scripts/assess-storage-runtime-image-20261102.py',
    'scripts/qualify-seaweedfs-raftstore-compat.py',
    'tests/fixtures/seaweedfs-raftstore-compat/compat_test.go',
    'tests/test_seaweedfs_452_generation31_image.py',
    'tests/test_storage_runtime_image.py', MANIFEST_PATH,
), 'releases/seaweedfs-452-generation30-build-manifest-20261103.json',
    '6e68ba7288bb0e7011003be34646fc01775a17aedff063d5c277e0c2841d0c8c')
if __name__ == '__main__':
    engine.main()
