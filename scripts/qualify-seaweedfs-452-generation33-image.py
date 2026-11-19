#!/usr/bin/env python3
"""Package and qualify a fresh build of the observed YAML33 vendor source."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("generation33_image", ROOT / "tools/storage_security/generation_image_v4.py")
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)

if __name__ == "__main__":
    engine.main()
