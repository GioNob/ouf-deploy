#!/usr/bin/env python3
"""Exact generation30 image qualification; no inherited generation29 outcomes."""
import importlib.util
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
ENGINE_PATH = 'tools/storage_security/generation_image_v1.py'
spec = importlib.util.spec_from_file_location('generation30_image_engine', ROOT / ENGINE_PATH)
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)
MANIFEST_PATH = 'releases/seaweedfs-452-generation30-build-manifest-20261103.json'
engine.configure(ROOT, 30, MANIFEST_PATH, (
    '.github/workflows/storage-452-generation30-image.yml',
    'scripts/qualify-seaweedfs-452-generation30-image.py',
    'scripts/readback-seaweedfs-452-generation30-image.py',
    ENGINE_PATH, 'tools/storage_security/generation_readback_v1.py',
    'scripts/assess-storage-sdk-lifecycle.py', 'tools/storage_security/runtime_image.py',
    'scripts/assess-storage-runtime-image-20261102.py',
    'scripts/qualify-seaweedfs-raftstore-compat.py',
    'tests/fixtures/seaweedfs-raftstore-compat/compat_test.go',
    'tests/test_seaweedfs_452_generation30_image.py',
    'tests/test_storage_runtime_image.py', MANIFEST_PATH,
), 'releases/seaweedfs-452-generation29-build-manifest-20261103.json',
    'cddbcd4f40c13cb8e86d49d9bf30dc85109aeb3fa50334d92c4690e622d952c9')
if __name__ == '__main__':
    engine.main()
