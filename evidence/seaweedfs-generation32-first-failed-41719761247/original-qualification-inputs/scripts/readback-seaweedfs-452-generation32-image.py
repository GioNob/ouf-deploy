#!/usr/bin/env python3
"""Independent readback for the exact generation32 image artifact."""
import importlib.util
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
candidate = load('generation32_candidate', 'scripts/qualify-seaweedfs-452-generation32-image.py').engine
engine = load('generation32_readback', 'tools/storage_security/generation_readback_v1.py')
engine.configure(ROOT, candidate)
if __name__ == '__main__':
    sys.exit(engine.main())
